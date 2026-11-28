use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use qrcode::{Color, EcLevel, QrCode};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    pub owner_id: i64,
    pub operator_subject: String,
    pub approval_profile: String,
    pub relay_subject: String,
    url: String,
    control_key_file: PathBuf,
    wrapping_key_file: PathBuf,
}

impl Relay {
    pub fn validate(&self, name: &str) -> Result<Url> {
        ensure!(
            valid_id(name)
                && self.owner_id > 0
                && !self.operator_subject.is_empty()
                && !self.relay_subject.is_empty()
                && self.operator_subject != self.relay_subject
                && !self.control_key_file.as_os_str().is_empty()
                && !self.wrapping_key_file.as_os_str().is_empty()
                && self.control_key_file != self.wrapping_key_file,
            "invalid Telegram relay configuration"
        );
        let raw = self
            .url
            .strip_prefix("https://")
            .context("must be a plain HTTPS origin")?;
        ensure!(
            !raw.is_empty() && !raw.contains(['/', '\\', '?', '#', '@']),
            "must be a plain HTTPS origin"
        );
        let url = Url::parse(&self.url)?;
        ensure!(
            url.port() != Some(0) && url.host_str().is_some(),
            "invalid HTTPS origin"
        );
        Ok(url)
    }

    pub fn validate_files(&self) -> Result<()> {
        let control = read_key(&self.control_key_file).context("Telegram control key")?;
        let wrapping = read_key(&self.wrapping_key_file).context("Telegram wrapping key")?;
        ensure!(
            *control != *wrapping,
            "Telegram control and wrapping keys must be distinct"
        );
        Ok(())
    }

    pub fn wrapping_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        read_key(&self.wrapping_key_file)
    }

    pub fn approval(&self, name: &str) -> (String, String) {
        let label = format!("Enroll Telegram account {} for relay {name}", self.owner_id);
        let text = format!(
            "keymint.telegram-enrollment.v1\0{name}\0{}\0{}\0{}",
            self.owner_id, self.url, self.relay_subject
        );
        (data_encoding::HEXLOWER.encode(&Sha256::digest(text)), label)
    }

    pub async fn call(
        &self,
        http: &Client,
        request: &Action<'_>,
    ) -> std::result::Result<Status, Failure> {
        let key = read_key(&self.control_key_file).map_err(|_| {
            Failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Telegram relay control key is unavailable",
            )
        })?;
        let bearer = Zeroizing::new(STANDARD.encode(&*key));
        let request = http
            .post(format!("{}/v1/enrollment", self.url))
            .bearer_auth(bearer.as_str())
            .json(request);
        let mut response = crate::telemetry::send(request, "POST")
            .await
            .map_err(|_| Failure(StatusCode::BAD_GATEWAY, "Telegram relay is unreachable"))?;
        let invalid = || {
            Failure(
                StatusCode::BAD_GATEWAY,
                "Telegram relay could not process enrollment",
            )
        };
        match response.status() {
            StatusCode::OK => (),
            StatusCode::CONFLICT => {
                return Err(Failure(
                    StatusCode::CONFLICT,
                    "Telegram relay rejected this enrollment state",
                ));
            }
            _ => return Err(invalid()),
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if body.len() + chunk.len() > 8192 {
                return Err(invalid());
            }
            body.extend_from_slice(&chunk);
        }
        let result: Status = serde_json::from_slice(&body).map_err(|_| invalid())?;
        if result.state.is_empty() {
            return Err(invalid());
        }
        Ok(result)
    }
}

pub fn valid_id(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn read_key(file: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut encoded = Zeroizing::new(String::new());
    File::open(file)?.take(129).read_to_string(&mut encoded)?;
    ensure!(encoded.len() <= 128, "invalid Telegram key file");
    let normalized = Zeroizing::new(encoded.trim().replace(['\r', '\n'], ""));
    let key = Zeroizing::new(STANDARD.decode(normalized.as_str())?);
    ensure!(key.len() == 32, "invalid Telegram key");
    Ok(key)
}

#[derive(Serialize)]
pub struct Action<'a> {
    pub action: &'a str,
    pub id: &'a str,
    pub owner_id: i64,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub password: &'a str,
}

#[derive(Deserialize, Serialize)]
pub struct Status {
    state: String,
    #[serde(default, skip_serializing)]
    login_url: String,
    expires_at: Option<DateTime<Utc>>,
}

impl Drop for Status {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.login_url.zeroize();
    }
}

pub struct Failure(pub StatusCode, pub &'static str);

impl Status {
    pub fn qr(&self, terminal: bool) -> std::result::Result<(&'static str, Vec<u8>), Failure> {
        let not_ready = || Failure(StatusCode::CONFLICT, "Telegram QR is not ready");
        let bad_token = || {
            Failure(
                StatusCode::BAD_GATEWAY,
                "Telegram relay returned an invalid QR token",
            )
        };
        let render = || Failure(StatusCode::BAD_GATEWAY, "Telegram QR could not be rendered");
        let url = Url::parse(&self.login_url).map_err(|_| not_ready())?;
        if self.state != "qr"
            || self.expires_at.is_none_or(|expiry| expiry <= Utc::now())
            || url.scheme() != "tg"
            || url.host_str() != Some("login")
            || !url.path().is_empty()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            return Err(not_ready());
        }
        let mut query = url.query_pairs();
        let (_, token) = query
            .next()
            .filter(|(name, _)| name == "token")
            .ok_or_else(not_ready)?;
        if query.next().is_some() {
            return Err(not_ready());
        }
        let token = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(token.as_bytes())
                .or_else(|_| URL_SAFE.decode(token.as_bytes()))
                .map_err(|_| bad_token())?,
        );
        if token.is_empty() {
            return Err(bad_token());
        }
        let matrix = QrCode::with_error_correction_level(self.login_url.as_bytes(), EcLevel::M)
            .map_err(|_| render())?;
        let border = 4;
        let width = matrix.width() + border * 2;
        let dark = |x: usize, y: usize| {
            x >= border
                && x < width - border
                && y >= border
                && y < width - border
                && matrix[(x - border, y - border)] == Color::Dark
        };
        if terminal {
            let mut text = String::new();
            for y in (0..width).step_by(2) {
                for x in 0..width {
                    text.push(match (dark(x, y), dark(x, y + 1)) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    });
                }
                text.push('\n');
            }
            return Ok(("text/plain; charset=utf-8", text.into_bytes()));
        }
        let size = 320;
        let scale = size / width;
        if scale == 0 {
            return Err(render());
        }
        let offset = (size - width * scale) / 2;
        let mut pixels = vec![255u8; size * size];
        for y in 0..width * scale {
            for x in 0..width * scale {
                if dark(x / scale, y / scale) {
                    pixels[(y + offset) * size + x + offset] = 0;
                }
            }
        }
        let mut bytes = Vec::new();
        let mut encoder = png::Encoder::new(&mut bytes, size as u32, size as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .and_then(|mut writer| writer.write_image_data(&pixels))
            .map_err(|_| render())?;
        Ok(("image/png", bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_requires_unexpired_valid_login_and_omits_login_url_from_status() -> Result<()> {
        let live = Status {
            state: "qr".into(),
            login_url: "tg://login?token=ZmFrZQ".into(),
            expires_at: Some(Utc::now() + chrono::Duration::minutes(1)),
        };
        assert!(!serde_json::to_string(&live)?.contains("ZmFrZQ"));
        let (kind, bytes) = live.qr(false).map_err(|_| anyhow::anyhow!("render PNG"))?;
        assert_eq!(kind, "image/png");
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        let (kind, bytes) = live
            .qr(true)
            .map_err(|_| anyhow::anyhow!("render terminal QR"))?;
        assert_eq!(kind, "text/plain; charset=utf-8");
        assert!(String::from_utf8(bytes)?.contains('█'));
        let expired = Status {
            state: live.state.clone(),
            login_url: live.login_url.clone(),
            expires_at: Some(Utc::now()),
        };
        assert!(matches!(
            expired.qr(false),
            Err(Failure(StatusCode::CONFLICT, _))
        ));
        Ok(())
    }
}
