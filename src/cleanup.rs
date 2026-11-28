use anyhow::{Context, Result, ensure};
use reqwest::{Client, StatusCode, Url};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

use crate::{config::validated_api_base, github::Identity, journal::Journal};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CleanupRecord {
    #[serde(rename = "ID")]
    id: String,
    profile: CleanupProfile,
    token: String,
    secret: String,
    due: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CleanupProfile {
    #[serde(default)]
    namespace: String,
    #[serde(default, rename = "APIBaseURL")]
    api_base_url: String,
    #[serde(default, rename = "ClientID")]
    client_id: String,
    #[serde(default)]
    client_secret: String,
}

pub struct Recovery {
    cipher: LessSafeKey,
    github: Client,
}

impl Recovery {
    pub fn open(state_path: &Path) -> Result<Self> {
        let mut key = Zeroizing::new(Vec::new());
        let rng = SystemRandom::new();
        if state_path.as_os_str().is_empty() {
            key.resize(32, 0);
            rng.fill(&mut key)
                .map_err(|_| anyhow::anyhow!("generate cleanup encryption key"))?;
        } else {
            let mut path = state_path.as_os_str().to_owned();
            path.push(".cleanup-key");
            let path = PathBuf::from(path);
            let file = match File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut generated = Zeroizing::new([0u8; 32]);
                    rng.fill(generated.as_mut())
                        .map_err(|_| anyhow::anyhow!("generate cleanup encryption key"))?;
                    let directory = path
                        .parent()
                        .filter(|directory| !directory.as_os_str().is_empty())
                        .unwrap_or(Path::new("."));
                    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
                    temporary.write_all(generated.as_ref())?;
                    temporary.as_file().sync_all()?;
                    match temporary.persist_noclobber(&path) {
                        Ok(_) => {
                            #[cfg(unix)]
                            File::open(directory)?.sync_all()?;
                        }
                        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error.error.into()),
                    };
                    File::open(path)?
                }
                Err(error) => return Err(error.into()),
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    file.metadata()?.permissions().mode() & 0o077 == 0,
                    "cleanup encryption key must be accessible only to its owner"
                );
            }
            file.take(33).read_to_end(&mut key)?;
        }
        let cipher = UnboundKey::new(&AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("invalid cleanup encryption key"))?;
        Ok(Self {
            cipher: LessSafeKey::new(cipher),
            github: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()?,
        })
    }

    pub fn reserve_kubernetes(
        &self,
        journal: &Journal,
        id: &str,
        namespace: &str,
        secret: &str,
        due: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let payload = if let Some(sealed) = journal.cleanup_record(id)? {
            let existing = self.decode(id, sealed)?;
            ensure!(
                existing.profile.namespace == namespace
                    && existing.secret.is_empty()
                    && !existing.token.is_empty(),
                "invalid existing Kubernetes cleanup reservation"
            );
            json!({
                "ID":id, "Profile": {"Namespace":namespace, "ClientID":existing.profile.client_id,
                "ClientSecret":existing.profile.client_secret, "APIBaseURL":existing.profile.api_base_url},
                "Token":existing.token, "Secret":secret, "Due":due,
            })
        } else {
            json!({"ID":id, "Profile":{"Namespace":namespace}, "Token":"", "Secret":secret,"Due":due})
        };
        self.reserve(journal, id, payload)
    }

    pub fn reserve_oauth(
        &self,
        journal: &Journal,
        id: &str,
        identity: &Identity,
        token: &str,
        namespace: &str,
        due: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        self.reserve(journal, id, json!({
            "ID":id, "Profile":{"Provider":"github_user","ClientID":identity.id,
            "ClientSecret":identity.secret.as_str(),"AllowedUserIDs":identity.users,"Namespace":namespace}, "Token":token,"Secret":"","Due":due,
        }))
    }

    fn reserve(&self, journal: &Journal, id: &str, payload: serde_json::Value) -> Result<()> {
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("generate cleanup nonce"))?;
        let mut data = Zeroizing::new(serde_json::to_vec(&payload)?);
        self.cipher
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(id.as_bytes()),
                &mut *data,
            )
            .map_err(|_| anyhow::anyhow!("encrypt cleanup record"))?;
        let mut record = nonce.to_vec();
        record.extend_from_slice(&data);
        journal.reserve_cleanup(id, &record)
    }

    fn decode(&self, id: &str, mut sealed: Vec<u8>) -> Result<CleanupRecord> {
        ensure!(
            sealed.len() >= 12 + AES_256_GCM.tag_len(),
            "invalid encrypted cleanup record"
        );
        let (nonce, data) = sealed.split_at_mut(12);
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| anyhow::anyhow!("invalid cleanup nonce"))?;
        let decrypted = self
            .cipher
            .open_in_place(nonce, Aad::from(id.as_bytes()), data)
            .map_err(|_| anyhow::anyhow!("decrypt cleanup record"))?;
        let parsed: serde_json::Result<CleanupRecord> = serde_json::from_slice(decrypted);
        use zeroize::Zeroize;
        data.zeroize();
        let record = parsed.map_err(|_| anyhow::anyhow!("invalid cleanup record"))?;
        ensure!(record.id == id, "cleanup record session ID mismatch");
        Ok(record)
    }

    pub async fn check(&self, journal: &Journal) -> Result<()> {
        for (id, sealed) in journal.cleanup_records().await? {
            self.decode(&id, sealed)
                .with_context(|| format!("validate cleanup record {id:?}"))?;
        }
        Ok(())
    }

    pub async fn collect_metrics(
        &self,
        journal: &Journal,
        metrics: &crate::metrics::Metrics,
    ) -> Result<()> {
        let records = journal.cleanup_records().await?;
        let mut oldest = 0;
        let now = chrono::Utc::now();
        let due = records.len() as i64;
        for (id, sealed) in records {
            if let Some(when) = self.decode(&id, sealed)?.due {
                oldest = oldest.max((now - when).num_seconds());
            }
        }
        metrics.cleanup(journal.cleanup_count().await?, due, oldest);
        Ok(())
    }

    pub async fn drain(
        &self,
        journal: &Journal,
        kubernetes: &Client,
        api: &Url,
        sa_token: &Path,
    ) -> Result<()> {
        let mut failures = 0;
        for (id, sealed) in journal.cleanup_records().await? {
            let record = self
                .decode(&id, sealed)
                .with_context(|| format!("load cleanup record {id:?}"))?;
            if self.revoke(record, kubernetes, api, sa_token).await.is_ok() {
                journal.remove_cleanup(id).await?;
            } else {
                failures += 1;
            }
        }
        ensure!(
            failures == 0,
            "remote revocation failed for {failures} cleanup record(s)"
        );
        Ok(())
    }

    pub async fn revoke_record(
        &self,
        journal: &Journal,
        id: &str,
        kubernetes: &Client,
        api: &Url,
        sa_token: &Path,
    ) -> Result<()> {
        if let Some(sealed) = journal.cleanup_record(id)? {
            self.revoke(self.decode(id, sealed)?, kubernetes, api, sa_token)
                .await?;
            journal.remove_cleanup(id.to_owned()).await?;
        }
        Ok(())
    }

    pub async fn revoke_oauth(
        &self,
        client_id: &str,
        client_secret: &str,
        token: &str,
        api: &str,
    ) -> Result<()> {
        let mut endpoint = validated_api_base(api)?;
        endpoint
            .path_segments_mut()
            .expect("validated HTTPS URL")
            .pop_if_empty()
            .extend(["applications", client_id, "token"]);
        let request = self
            .github
            .delete(endpoint)
            .basic_auth(client_id, Some(client_secret))
            .header("Accept", "application/vnd.github+json")
            .json(&json!({"access_token": token}));
        let status = crate::telemetry::send(request, "DELETE").await?.status();
        ensure!(
            matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_FOUND),
            "GitHub cleanup returned HTTP {}",
            status.as_u16()
        );
        Ok(())
    }

    async fn revoke(
        &self,
        mut record: CleanupRecord,
        kubernetes: &Client,
        api: &Url,
        sa_token: &Path,
    ) -> Result<()> {
        let token = Zeroizing::new(std::mem::take(&mut record.token));
        let client_secret = Zeroizing::new(std::mem::take(&mut record.profile.client_secret));
        let github = async {
            if token.is_empty() {
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(
                !record.profile.client_id.is_empty() && !client_secret.is_empty(),
                "missing original GitHub OAuth identity"
            );
            self.revoke_oauth(
                &record.profile.client_id,
                client_secret.as_str(),
                token.as_str(),
                &record.profile.api_base_url,
            )
            .await
        };
        let kube = async {
            if record.secret.is_empty() {
                return Ok(());
            }
            revoke_kubernetes(
                kubernetes,
                api,
                sa_token,
                &record.profile.namespace,
                &record.secret,
            )
            .await
        };
        let (github, kube) = tokio::join!(github, kube);
        github.and(kube)
    }
}

pub async fn revoke_kubernetes(
    client: &Client,
    api: &Url,
    sa_token: &Path,
    namespace: &str,
    secret: &str,
) -> Result<()> {
    ensure!(
        !namespace.is_empty()
            && !matches!(namespace, "." | "..")
            && !secret.is_empty()
            && !matches!(secret, "." | ".."),
        "invalid Kubernetes cleanup coordinates"
    );
    let mut endpoint = api.clone();
    endpoint
        .path_segments_mut()
        .expect("validated Kubernetes HTTPS URL")
        .clear()
        .extend(["api", "v1", "namespaces", namespace, "secrets", secret]);
    let token = Zeroizing::new(tokio::fs::read_to_string(sa_token).await?);
    let request = client.delete(endpoint).bearer_auth(token.trim());
    let status = crate::telemetry::send(request, "DELETE").await?.status();
    ensure!(
        status.is_success() || status == StatusCode::NOT_FOUND,
        "Kubernetes cleanup returned HTTP {}",
        status.as_u16()
    );
    Ok(())
}

impl Drop for CleanupRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
        self.profile.client_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn reads_go_aes_gcm_record_and_checks_associated_session() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state = dir.path().join("state.db");
        let key = dir.path().join("state.db.cleanup-key");
        let mut file = tempfile::NamedTempFile::new_in(dir.path())?;
        file.write_all(&[0u8; 32])?;
        file.persist(&key)?;
        let recovery = Recovery::open(&state)?;
        // AES-GCM output from Go's cipher.Seal using synthetic values and a zero fixture key.
        let sealed = STANDARD.decode(concat!(
            "AAAAAAAAAAAAAAAAtYUJeW9aSSsqOqCgztGxOiISbKxeyk9W69nXwBRrUP2tK9JNb3DDDySbLQZrLnWbLiSllcj/XQ",
            "pDGnSb33lIev2l/wMDhA90DPzJjjXCAsPOyj2S+uzARJ7IaRQxc27IyIgSuUyp+GUP+f+klkmpe/Yo24lAQ5SDEL2Y",
            "IfJnCTwmGqPWFrSRn1SThRZRsPHSzn8n+MBISs6MdYFC2mD4DdRKjtPRe89n2jvH5gVy5+iVC1oqF3gFXd87llu",
            "eJgZKVM8NpWluxyzFyDHINpJy9oHjIBSmthbbmVqPWlW4Xo1Mk0VY+yV9KeotN4Oy"
        ))?;
        assert!(recovery.decode("E-other", sealed.clone()).is_err());
        let record = recovery.decode("E-test", sealed)?;
        assert_eq!(record.profile.client_id, "fixture-app");
        assert_eq!(record.profile.client_secret, "fixture-secret");
        assert_eq!(record.profile.namespace, "test");
        assert_eq!(record.token, "fixture-token");
        Ok(())
    }
}
