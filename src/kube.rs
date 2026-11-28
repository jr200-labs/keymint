use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Client, Method, Response, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::path::Path;
use zeroize::Zeroizing;

pub struct Issuer<'a> {
    pub client: &'a Client,
    pub cluster: &'a Url,
    pub sa_token: &'a Path,
}

#[derive(Serialize)]
pub struct Credential {
    provider: &'static str,
    token: String,
    expires_at: DateTime<Utc>,
}

impl Credential {
    pub fn github(token: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            provider: "github_user",
            token,
            expires_at,
        }
    }
}

impl Issuer<'_> {
    async fn request(
        &self,
        method: Method,
        path: &[&str],
        data: Option<Value>,
    ) -> Result<Response> {
        let mut endpoint = self.cluster.clone();
        endpoint
            .path_segments_mut()
            .expect("validated Kubernetes HTTPS URL")
            .clear()
            .extend(path);
        let token = Zeroizing::new(tokio::fs::read_to_string(self.sa_token).await?);
        let method_name = if method == Method::GET { "GET" } else { "POST" };
        let mut request = self
            .client
            .request(method, endpoint)
            .bearer_auth(token.trim());
        if let Some(body) = data {
            request = request.json(&body);
        }
        Ok(crate::telemetry::send(request, method_name).await?)
    }

    pub async fn issue(
        &self,
        namespace: &str,
        account: &str,
        secret: &str,
        expires: DateTime<Utc>,
    ) -> Result<Credential> {
        let namespace_path = ["api", "v1", "namespaces", namespace];
        let mut path = namespace_path.to_vec();
        path.push("secrets");
        let created = self
            .request(
                Method::POST,
                &path,
                Some(json!({
                    "apiVersion": "v1", "kind":"Secret",
                    "metadata": {"name":secret,"labels":{"app.kubernetes.io/managed-by":"keymint"}},
                })),
            )
            .await?;
        ensure!(
            created.status().is_success() || created.status() == StatusCode::CONFLICT,
            "Kubernetes Secret creation returned HTTP {}",
            created.status().as_u16()
        );
        path.push(secret);
        #[derive(Deserialize)]
        struct Secret {
            metadata: Metadata,
        }
        #[derive(Deserialize)]
        struct Metadata {
            uid: String,
        }
        let details: Secret = read(self.request(Method::GET, &path, None).await?).await?;
        ensure!(
            !details.metadata.uid.is_empty(),
            "Kubernetes Secret has no UID"
        );
        let seconds = (expires - Utc::now()).num_seconds().max(600);
        path.truncate(namespace_path.len());
        path.extend(["serviceaccounts", account, "token"]);
        let response = self
            .request(
                Method::POST,
                &path,
                Some(json!({
                    "apiVersion":"authentication.k8s.io/v1", "kind":"TokenRequest",
                    "spec":{"expirationSeconds":seconds, "boundObjectRef":{
                        "apiVersion":"v1","kind":"Secret","name":secret,"uid":details.metadata.uid,
                    }},
                })),
            )
            .await?;
        #[derive(Deserialize)]
        struct Requested {
            status: Token,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Token {
            token: String,
            expiration_timestamp: DateTime<Utc>,
        }
        let issued: Requested = read(response)
            .await
            .context("request Kubernetes emergency token")?;
        ensure!(
            !issued.status.token.is_empty(),
            "Kubernetes returned an empty token"
        );
        Ok(Credential {
            provider: "kubernetes",
            token: issued.status.token,
            expires_at: expires.min(issued.status.expiration_timestamp),
        })
    }
}

async fn read<T: DeserializeOwned>(mut response: Response) -> Result<T> {
    ensure!(
        response.status().is_success(),
        "Kubernetes returned HTTP {}",
        response.status().as_u16()
    );
    let mut buffer = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            buffer.len() + chunk.len() <= 1 << 20,
            "Kubernetes response exceeds 1 MiB"
        );
        buffer.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&buffer)?)
}
