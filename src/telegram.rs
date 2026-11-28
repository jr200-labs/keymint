use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, StatusCode, Url};
use serde::Deserialize;
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    time::{self, Interval},
};
use zeroize::Zeroizing;

struct Enrollment<'a> {
    origin: Url,
    token_file: &'a Path,
    http: Client,
}

#[derive(Deserialize)]
struct State {
    #[serde(default)]
    id: String,
    state: String,
    #[serde(default)]
    verification_uri: String,
    #[serde(default)]
    approval_label: String,
    expires_at: Option<DateTime<Utc>>,
}

fn plain_https(raw: &str) -> Result<Url> {
    let authority = raw
        .strip_prefix("https://")
        .context("expected HTTPS URL")?
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    ensure!(
        !authority.is_empty() && !authority.contains('@') && !raw.contains('\\'),
        "invalid HTTPS URL"
    );
    Ok(Url::parse(raw)?)
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

pub async fn enroll(raw_url: &str, relay: &str, token_file: &Path) -> Result<()> {
    let origin = plain_https(raw_url)?;
    ensure!(
        origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.port() != Some(0)
            && valid_id(relay)
            && !token_file.as_os_str().is_empty(),
        "a Keymint HTTPS origin, relay name and operator token file are required"
    );
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "Telegram enrollment requires a private interactive terminal"
    );
    let client = Enrollment {
        origin,
        token_file,
        http: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?,
    };
    let path = format!("/telegram-enrollments/{relay}");
    let mut tick = time::interval_at(
        time::Instant::now() + Duration::from_secs(2),
        Duration::from_secs(2),
    );
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let id = tokio::select! {
        approval = client.approve(&path, &mut tick) => approval?,
        _ = tokio::signal::ctrl_c() => bail!("Telegram enrollment interrupted"),
    };
    let path = format!("{path}/{id}");
    let result = tokio::select! {
        enrollment = client.finish(&path, &mut tick) => enrollment,
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("Telegram enrollment interrupted")),
    };
    if result.is_err() {
        let _ = time::timeout(
            Duration::from_secs(3),
            client.request(
                Method::POST,
                &format!("{path}/cancel"),
                "application/json",
                None,
            ),
        )
        .await;
    }
    result
}

impl Enrollment<'_> {
    async fn request(
        &self,
        method: Method,
        path: &str,
        accept: &str,
        payload: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let file = tokio::fs::File::open(self.token_file)
            .await
            .context("open operator token file")?;
        let mut token = Zeroizing::new(String::new());
        file.take(8193)
            .read_to_string(&mut token)
            .await
            .context("read operator token file")?;
        ensure!(
            !token.trim().is_empty() && token.len() <= 8192,
            "invalid operator token file"
        );
        let mut request = self
            .http
            .request(method, self.origin.join(path)?)
            .bearer_auth(token.trim())
            .header("Accept", accept)
            .header("Content-Type", "application/json");
        if let Some(payload) = payload {
            request = request.body(payload);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Keymint enrollment endpoint is unreachable"))?;
        let status = response.status();
        let mut data = Vec::new();
        if status == StatusCode::OK {
            while let Some(chunk) = response
                .chunk()
                .await
                .context("read Keymint enrollment response")?
            {
                ensure!(
                    data.len() + chunk.len() <= 32768,
                    "invalid Keymint enrollment response"
                );
                data.extend_from_slice(&chunk);
            }
        }
        Ok((status, data))
    }

    async fn state(&self, method: Method, path: &str, payload: Option<Vec<u8>>) -> Result<State> {
        let (status, data) = self
            .request(method, path, "application/json", payload)
            .await?;
        ensure!(
            status == StatusCode::OK,
            "Keymint enrollment request returned HTTP {}",
            status.as_u16()
        );
        let state: State = serde_json::from_slice(&data)
            .context("Keymint returned an invalid enrollment state")?;
        ensure!(
            !state.state.is_empty(),
            "Keymint returned an invalid enrollment state"
        );
        Ok(state)
    }

    async fn approve(&self, path: &str, tick: &mut Interval) -> Result<String> {
        let mut state = self.state(Method::POST, path, None).await?;
        let verification =
            plain_https(&state.verification_uri).context("invalid passkey ceremony URL")?;
        ensure!(
            valid_id(&state.id) && state.state == "awaiting_passkey",
            "Keymint did not return a valid passkey ceremony"
        );
        ensure!(
            state.approval_label.chars().all(|ch| !ch.is_control()),
            "invalid passkey approval label"
        );
        println!(
            "{}\nApprove with your passkey at {verification}",
            state.approval_label
        );
        let id = state.id.clone();
        let session_path = format!("/emergency/sessions/{id}");
        while state.state == "awaiting_passkey" {
            tick.tick().await;
            state = self.state(Method::GET, &session_path, None).await?;
        }
        ensure!(
            state.state == "active",
            "passkey approval ended in state {:?}",
            state.state
        );
        Ok(id)
    }

    async fn finish(&self, path: &str, tick: &mut Interval) -> Result<()> {
        let mut state = self
            .state(Method::POST, &format!("{path}/start"), None)
            .await?;
        let mut shown_until = None;
        loop {
            match state.state.as_str() {
                "qr" if state.expires_at != shown_until
                    && state.expires_at.is_some_and(|expires| expires > Utc::now()) =>
                {
                    let (status, qr) = self
                        .request(Method::GET, &format!("{path}/qr"), "text/plain", None)
                        .await?;
                    if status == StatusCode::OK {
                        let qr = String::from_utf8(qr).context("invalid enrollment QR text")?;
                        ensure!(
                            qr.chars().all(|ch| !ch.is_control() || ch == '\n'),
                            "invalid enrollment QR text"
                        );
                        println!(
                            "Scan with your already signed-in Telegram app.\n\x1b[30;47m{}\x1b[0m",
                            qr.replace('\n', "\x1b[0m\n\x1b[30;47m")
                        );
                        shown_until = state.expires_at;
                    } else {
                        ensure!(
                            status == StatusCode::CONFLICT,
                            "Keymint QR request returned HTTP {}",
                            status.as_u16()
                        );
                    }
                }
                "password_required" => {
                    print!("Telegram two-step verification password: ");
                    io::stdout().flush()?;
                    let password = Zeroizing::new(rpassword::read_password()?);
                    #[derive(serde::Serialize)]
                    struct Password<'a> {
                        password: &'a str,
                    }
                    let body = serde_json::to_vec(&Password {
                        password: password.as_str(),
                    })?;
                    drop(password);
                    state = self
                        .state(Method::POST, &format!("{path}/password"), Some(body))
                        .await?;
                }
                "verified" => {
                    state = self
                        .state(Method::POST, &format!("{path}/commit"), None)
                        .await?;
                }
                "enrolled" => {
                    println!("Telegram account enrolled.");
                    return Ok(());
                }
                "qr" | "starting" | "verifying" | "committing" => {}
                _ => bail!("Telegram enrollment ended in state {:?}", state.state),
            }
            if state.state == "enrolled" {
                continue;
            }
            tick.tick().await;
            state = self
                .state(Method::GET, &format!("{path}/status"), None)
                .await?;
        }
    }
}
