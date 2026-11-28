use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, de::DeserializeOwned};
use std::{fs, path::Path, time::Duration};
use zeroize::Zeroizing;

pub struct Identity {
    pub id: String,
    pub secret: Zeroizing<String>,
    pub users: Vec<i64>,
}

impl Identity {
    pub fn load(
        id: &str,
        id_file: &Path,
        secret: &str,
        secret_file: &Path,
        users: &[i64],
        users_file: &Path,
    ) -> Result<Self> {
        let id = read_field(id, id_file).context("read GitHub client ID")?;
        let secret =
            Zeroizing::new(read_field(secret, secret_file).context("read GitHub client secret")?);
        let users = if users_file.as_os_str().is_empty() {
            users.to_vec()
        } else {
            fs::read_to_string(users_file)
                .context("read allowed GitHub user IDs")?
                .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                .filter(|field| !field.is_empty())
                .map(str::parse)
                .collect::<std::result::Result<Vec<i64>, _>>()
                .context("allowed GitHub user IDs file contains a non-numeric value")?
        };
        ensure!(
            !id.is_empty()
                && !secret.is_empty()
                && !users.is_empty()
                && users.iter().all(|id| *id > 0),
            "client ID, client secret and allowed user IDs are required"
        );
        Ok(Self { id, secret, users })
    }
}

fn read_field(value: &str, file: &Path) -> Result<String> {
    if file.as_os_str().is_empty() {
        Ok(value.to_owned())
    } else {
        Ok(fs::read_to_string(file)?.trim().to_owned())
    }
}

pub struct Device {
    code: Zeroizing<String>,
    pub user_code: String,
    pub verification_uri: String,
    interval: i64,
    pub next_poll: DateTime<Utc>,
}

impl Device {
    pub async fn start(client: &Client, identity: &Identity, scopes: &[String]) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Started {
            device_code: String,
            user_code: String,
            verification_uri: String,
            interval: i64,
            error: String,
        }
        impl Default for Started {
            fn default() -> Self {
                Self {
                    device_code: String::new(),
                    user_code: String::new(),
                    verification_uri: String::new(),
                    interval: 5,
                    error: String::new(),
                }
            }
        }
        let requested = scopes.join(" ");
        let started: Started = request_json(
            client.post("https://github.com/login/device/code").form(&[
                ("client_id", identity.id.as_str()),
                ("scope", requested.as_str()),
            ]),
            "POST",
        )
        .await?;
        match started.error.as_str() {
            "" => (),
            "unauthorized_client" | "incorrect_client_credentials" | "device_flow_disabled" => {
                anyhow::bail!("GitHub device flow: {}", started.error)
            }
            _ => anyhow::bail!("GitHub rejected the device flow request"),
        }
        let uri = reqwest::Url::parse(&started.verification_uri)
            .context("invalid GitHub verification URL")?;
        ensure!(
            !started.device_code.trim().is_empty()
                && !started.user_code.trim().is_empty()
                && uri.scheme() == "https"
                && uri.host_str() == Some("github.com")
                && uri.username().is_empty()
                && uri.password().is_none(),
            "GitHub returned an invalid device flow response"
        );
        Ok(Self {
            code: Zeroizing::new(started.device_code),
            user_code: started.user_code,
            verification_uri: started.verification_uri,
            interval: started.interval.clamp(5, 5400),
            next_poll: Utc::now(),
        })
    }

    pub async fn poll(&mut self, client: &Client, identity: &Identity) -> Result<Poll> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Response {
            access_token: String,
            scope: String,
            error: String,
        }
        self.next_poll = Utc::now() + chrono::Duration::seconds(self.interval);
        let response: Response = request_json(
            client
                .post("https://github.com/login/oauth/access_token")
                .form(&[
                    ("client_id", identity.id.as_str()),
                    ("device_code", self.code.as_str()),
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ]),
            "POST",
        )
        .await?;
        if !response.access_token.is_empty() {
            let mut scopes: Vec<String> = response
                .scope
                .split([',', ' '])
                .filter(|scope| !scope.is_empty())
                .map(str::to_owned)
                .collect();
            scopes.sort_unstable();
            scopes.dedup();
            return Ok(Poll::Token(Zeroizing::new(response.access_token), scopes));
        }
        match response.error.as_str() {
            "authorization_pending" => Ok(Poll::Pending),
            "slow_down" => {
                self.interval = (self.interval + 5).min(5400);
                self.next_poll = Utc::now() + chrono::Duration::seconds(self.interval);
                Ok(Poll::Pending)
            }
            "expired_token" | "token_expired" => Ok(Poll::Expired),
            "access_denied"
            | "incorrect_device_code"
            | "incorrect_client_credentials"
            | "unsupported_grant_type"
            | "device_flow_disabled" => Ok(Poll::Rejected),
            _ => anyhow::bail!("GitHub device flow did not issue a token"),
        }
    }
}

pub enum Poll {
    Pending,
    Expired,
    Rejected,
    Token(Zeroizing<String>, Vec<String>),
}

pub fn client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?)
}

pub async fn verify_user(client: &Client, token: &str, allowed: &[i64]) -> Result<()> {
    #[derive(Deserialize)]
    struct User {
        id: i64,
    }
    let user: User = request_json(
        client.get("https://api.github.com/user").bearer_auth(token),
        "GET",
    )
    .await?;
    ensure!(
        allowed.contains(&user.id),
        "authenticated GitHub user is not allowed for this profile"
    );
    Ok(())
}

async fn request_json<T: DeserializeOwned>(
    request: RequestBuilder,
    method: &'static str,
) -> Result<T> {
    let request = request
        .header("Accept", "application/json")
        .header("User-Agent", "keymint");
    let mut response = crate::telemetry::send(request, method).await?;
    ensure!(
        response.status().is_success(),
        "GitHub returned HTTP {}",
        response.status().as_u16()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 1 << 20,
            "GitHub response exceeds 1 MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
