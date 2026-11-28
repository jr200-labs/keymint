use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use zeroize::Zeroizing;

use crate::config::Key;

#[derive(Debug)]
pub struct PermissionsNotGranted;

impl std::fmt::Display for PermissionsNotGranted {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("the permissions requested are not granted to this installation")
    }
}
impl std::error::Error for PermissionsNotGranted {}

#[derive(Debug)]
pub struct GithubHttpError(pub StatusCode);

impl std::fmt::Display for GithubHttpError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "mint: GitHub returned HTTP {}", self.0.as_u16())
    }
}
impl std::error::Error for GithubHttpError {}

#[derive(Serialize)]
struct Claims {
    iat: i64,
    exp: i64,
    iss: i64,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Token {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

pub async fn mint(key: &Key, timeout: Duration) -> Result<Token> {
    let client = client()?;
    tokio::time::timeout(timeout, mint_token(key, &client, &Scope::default()))
        .await
        .context("mint: request timed out")?
}

pub fn client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scope {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub permissions: BTreeMap<String, String>,
}

impl Scope {
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            self.repositories.len() <= 100,
            "token scope exceeds 100 repositories"
        );
        let valid_name = |name: &str| {
            (1..=100).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        };
        let mut seen = BTreeSet::new();
        ensure!(
            self.repositories
                .iter()
                .all(|repo| valid_name(repo) && seen.insert(repo)),
            "token scope contains an invalid or duplicate repository"
        );
        ensure!(
            self.permissions.iter().all(|(name, level)| valid_name(name)
                && matches!(
                    level.as_str(),
                    "read" | "write" | "admin" | "triage" | "maintain"
                )),
            "token scope contains an invalid permission"
        );
        self.repositories.sort();
        Ok(())
    }
}

pub async fn mint_token(key: &Key, client: &Client, scope: &Scope) -> Result<Token> {
    let pem = Zeroizing::new(if key.private_key_sops.as_os_str().is_empty() {
        tokio::fs::read(&key.private_key_file)
            .await
            .context("mint: read private key")?
    } else {
        let result = tokio::process::Command::new("sops")
            .args(["-d", "--"])
            .arg(&key.private_key_sops)
            .kill_on_drop(true)
            .output()
            .await
            .context("sops: decrypt private key")?;
        ensure!(
            result.status.success(),
            "sops: decryption failed ({})",
            result.status
        );
        result.stdout
    });
    exchange(key, client, scope, &pem, None).await
}

pub struct ExchangeObservation<'a> {
    pub offset: &'a std::sync::atomic::AtomicI64,
    pub metrics: &'a crate::metrics::Metrics,
    pub base: &'a str,
}

pub async fn exchange(
    key: &Key,
    client: &Client,
    scope: &Scope,
    pem: &[u8],
    observation: Option<ExchangeObservation<'_>>,
) -> Result<Token> {
    use std::sync::atomic::Ordering::Relaxed;
    let signing_key = EncodingKey::from_rsa_pem(pem).context("mint: parse RSA private key")?;
    let now = Utc::now().timestamp()
        + observation
            .as_ref()
            .map_or(0, |observation| observation.offset.load(Relaxed));
    let claims = Claims {
        iat: now - 60,
        exp: now + 9 * 60,
        iss: key.app_id,
    };
    let jwt = Zeroizing::new(
        encode(&Header::new(Algorithm::RS256), &claims, &signing_key).context("mint: sign JWT")?,
    );

    let mut endpoint = key.api_base()?;
    endpoint
        .path_segments_mut()
        .expect("validated HTTPS URL")
        .pop_if_empty()
        .extend([
            "app",
            "installations",
            &key.install_id.to_string(),
            "access_tokens",
        ]);
    let mut request = client
        .post(endpoint)
        .bearer_auth(jwt.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "keymint");
    if !scope.repositories.is_empty() || !scope.permissions.is_empty() {
        request = request.json(scope);
    }
    let started = std::time::Instant::now();
    let result = crate::telemetry::send(request, "POST").await;
    if let Some(observation) = &observation {
        match &result {
            Ok(response) => observation.metrics.exchange(
                observation.base,
                &response.status().as_u16().to_string(),
                Some(response.headers()),
                started,
            ),
            Err(_) => {
                observation
                    .metrics
                    .exchange(observation.base, "transport_error", None, started)
            }
        }
    }
    let mut response = result.context("mint: exchange installation token")?;
    let status = response.status();
    if let Some(observation) = &observation
        && let Some(date) = response
            .headers()
            .get("Date")
            .and_then(|date| date.to_str().ok())
        && let Ok(time) = httpdate::parse_http_date(date)
    {
        let server = DateTime::<Utc>::from(time).timestamp();
        let seconds = server - Utc::now().timestamp();
        observation.offset.store(seconds, Relaxed);
        observation.metrics.clock(observation.base, seconds);
    }
    if !matches!(
        status,
        StatusCode::CREATED | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return Err(GithubHttpError(status).into());
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.context("mint: read response")? {
        ensure!(
            body.len() + chunk.len() <= 1 << 20,
            "mint: GitHub response exceeds 1 MiB"
        );
        body.extend_from_slice(&chunk);
    }
    if status == StatusCode::UNPROCESSABLE_ENTITY {
        if serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|value| {
            value["message"] == "The permissions requested are not granted to this installation."
        }) {
            return Err(PermissionsNotGranted.into());
        }
        return Err(GithubHttpError(status).into());
    }
    let token: Token = serde_json::from_slice(&body).context("mint: parse response")?;
    ensure!(
        !token.token.is_empty() && !token.token.contains(['\r', '\n', '\0']),
        "mint: invalid installation token"
    );
    Ok(token)
}
