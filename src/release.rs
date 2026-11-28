use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use crypto_box::{PublicKey, aead::OsRng};
use reqwest::{Client, Url};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::PathBuf};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd, Default)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Repository,
    Organization,
}

#[derive(Deserialize, Serialize)]
pub struct Target {
    pub github_owner: String,
    pub github_repository: String,
    #[serde(default, deserialize_with = "parse_scope")]
    pub secret_scope: Scope,
}

fn parse_scope<'de, D: serde::Deserializer<'de>>(input: D) -> std::result::Result<Scope, D::Error> {
    let scope = Option::<String>::deserialize(input)?;
    match scope.as_deref() {
        None | Some("" | "repository") => Ok(Scope::Repository),
        Some("organization") => Ok(Scope::Organization),
        _ => Err(serde::de::Error::custom("invalid Actions secret scope")),
    }
}

impl Target {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            identifier(&self.github_owner) && identifier(&self.github_repository),
            "invalid Actions secret target"
        );
        Ok(())
    }

    pub fn repository(&self) -> String {
        format!("{}/{}", self.github_owner, self.github_repository)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub github_key: String,
    kind: String,
    private_key_file: PathBuf,
    pub repositories: Vec<String>,
    secret_name: String,
    secret_scopes: Option<Vec<Scope>>,
}

impl Key {
    pub fn scopes(&self) -> &[Scope] {
        self.secret_scopes
            .as_deref()
            .unwrap_or(&[Scope::Repository])
    }

    pub fn validate(&self, name: &str) -> Result<()> {
        ensure!(
            identifier(name)
                && self.kind == "sparkle_ed25519"
                && !self.private_key_file.as_os_str().is_empty()
                && !self.repositories.is_empty()
                && self.secret_name == "SPARKLE_EDDSA_PRIVATE_KEY",
            "invalid release signing key configuration"
        );
        ensure!(!self.scopes().is_empty(), "secret_scopes must not be empty");
        let mut scopes = std::collections::BTreeSet::new();
        ensure!(
            self.scopes().iter().all(|scope| scopes.insert(scope)),
            "duplicate release key secret scope"
        );
        let mut repositories = std::collections::BTreeSet::new();
        ensure!(
            self.repositories
                .iter()
                .all(|repo| repo.split_once('/').is_some_and(|(owner, name)| {
                    identifier(owner) && identifier(name) && repositories.insert(repo)
                })),
            "invalid or duplicate release key repository bindings"
        );
        Ok(())
    }

    pub fn validate_file(&self) -> Result<()> {
        self.read().map(|_| ())
    }

    fn read(&self) -> Result<(Zeroizing<String>, Vec<u8>)> {
        let file =
            File::open(&self.private_key_file).context("release signing key is unavailable")?;
        ensure!(
            file.metadata()?.is_file(),
            "release signing key is unavailable"
        );
        let mut bytes = Zeroizing::new(String::new());
        file.take(4097)
            .read_to_string(&mut bytes)
            .context("release signing key is unavailable")?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= 4096,
            "release signing key is unavailable"
        );
        let text = Zeroizing::new(bytes.trim().to_owned());
        let compact = Zeroizing::new(text.replace(['\r', '\n'], ""));
        let bundle = Zeroizing::new(
            STANDARD
                .decode(compact.as_bytes())
                .context("invalid Sparkle Ed25519 export")?,
        );
        ensure!(bundle.len() == 96, "invalid Sparkle Ed25519 export");
        let key = Ed25519KeyPair::from_seed_unchecked(&bundle[..32])
            .map_err(|_| anyhow::anyhow!("invalid Sparkle Ed25519 seed"))?;
        let public = key.public_key().as_ref();
        ensure!(
            &bundle[32..64] == public && &bundle[64..] == public,
            "inconsistent Sparkle Ed25519 export"
        );
        Ok((text, public.to_vec()))
    }

    pub fn seal(&self, target: Target, destination: Destination) -> Result<Sealed> {
        let (text, public) = self.read()?;
        let recipient = PublicKey::from(destination.recipient);
        let ciphertext = recipient
            .seal(&mut OsRng, text.as_bytes())
            .map_err(|_| anyhow::anyhow!("seal release signing key"))?;
        Ok(Sealed {
            target,
            public_key: STANDARD.encode(public),
            secret_name: self.secret_name.clone(),
            destination_key_id: destination.key_id,
            encrypted_value: STANDARD.encode(ciphertext),
        })
    }
}

fn identifier(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

pub struct Destination {
    pub key_id: String,
    pub public_key: String,
    recipient: [u8; 32],
}

#[derive(Serialize)]
pub struct Sealed {
    #[serde(flatten)]
    target: Target,
    public_key: String,
    secret_name: String,
    destination_key_id: String,
    encrypted_value: String,
}

pub async fn resolve(
    http: &Client,
    mut base: Url,
    token: &str,
    target: &Target,
) -> Result<Destination> {
    target.validate()?;
    {
        let mut path = base.path_segments_mut().expect("validated HTTPS URL");
        path.pop_if_empty();
        match target.secret_scope {
            Scope::Repository => {
                path.extend(["repos", &target.github_owner, &target.github_repository])
            }
            Scope::Organization => path.extend(["orgs", &target.github_owner]),
        };
        path.extend(["actions", "secrets", "public-key"]);
    }
    let request = http
        .get(base)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "keymint");
    let mut response = crate::telemetry::send(request, "GET")
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 8192,
            "invalid Actions encryption key response"
        );
        bytes.extend_from_slice(&chunk);
    }
    #[derive(Deserialize)]
    struct KeyResponse {
        key_id: String,
        key: String,
    }
    let result: KeyResponse = serde_json::from_slice(&bytes)?;
    ensure!(
        !result.key_id.is_empty() && result.key_id.len() <= 128,
        "invalid Actions encryption key ID"
    );
    let decoded = STANDARD.decode(&result.key)?;
    let recipient = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Actions encryption key"))?;
    Ok(Destination {
        key_id: result.key_id,
        public_key: result.key,
        recipient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sealed_key_keeps_destination_metadata_and_original_export() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sparkle-export");
        let seed = [5u8; 32];
        let signing = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let public = signing.public_key().as_ref();
        let export = STANDARD.encode([seed.as_slice(), public, public].concat());
        std::fs::write(&path, &export)?;
        let key: Key = serde_json::from_value(json!({
            "github_key":"fixture","kind":"sparkle_ed25519","private_key_file":path,
            "repositories":["owner/project"],"secret_name":"SPARKLE_EDDSA_PRIVATE_KEY",
            "secret_scopes":["organization"],
        }))?;
        key.validate("fixture")?;
        let receiving = crypto_box::SecretKey::from([3u8; 32]);
        let recipient = receiving.public_key().to_bytes();
        let sealed = key.seal(
            Target {
                github_owner: "owner".into(),
                github_repository: "project".into(),
                secret_scope: Scope::Organization,
            },
            Destination {
                key_id: "recipient-1".into(),
                public_key: STANDARD.encode(recipient),
                recipient,
            },
        )?;
        let encoded = serde_json::to_value(&sealed)?;
        assert_eq!(encoded["github_owner"], "owner");
        assert_eq!(encoded["github_repository"], "project");
        assert_eq!(encoded["secret_scope"], "organization");
        assert_eq!(encoded["destination_key_id"], "recipient-1");
        assert_eq!(encoded["public_key"], STANDARD.encode(public));
        assert!(!encoded.to_string().contains(&export));
        let cipher = STANDARD.decode(&sealed.encrypted_value)?;
        assert_eq!(receiving.unseal(&cipher).unwrap(), export.as_bytes());
        Ok(())
    }
}
