use anyhow::{Context, Result, ensure};
use chrono::Utc;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard, Semaphore};
use zeroize::Zeroizing;

use crate::{
    breaker::Breaker,
    config::Key,
    metrics::Metrics,
    mint::{self, ExchangeObservation, Scope, Token},
};

const CACHE_SIZE: usize = 1024;
const BACKGROUND_REFRESH_SECONDS: i64 = 300;
const SYNCHRONOUS_REFRESH_SECONDS: i64 = 60;
const REFRESH_COOLDOWN: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Slot {
    current: Mutex<Option<Token>>,
    refresh: Arc<AsyncMutex<Option<Instant>>>,
}

type Cache = HashMap<[u8; 32], (Arc<Slot>, Instant)>;

struct Endpoint {
    exchange: Semaphore,
    clock_offset: std::sync::atomic::AtomicI64,
    breaker: Breaker,
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            exchange: Semaphore::new(50),
            clock_offset: Default::default(),
            breaker: Breaker::default(),
        }
    }
}

#[derive(Clone)]
pub struct InstallationBroker {
    client: Client,
    timeout: Duration,
    cache: Arc<Mutex<Cache>>,
    endpoints: Arc<Mutex<HashMap<String, Arc<Endpoint>>>>,
    metrics: Arc<Metrics>,
}

impl InstallationBroker {
    pub fn new(timeout: Duration, metrics: Arc<Metrics>) -> Result<Self> {
        Ok(Self {
            client: mint::client()?,
            timeout,
            cache: Arc::default(),
            endpoints: Arc::default(),
            metrics,
        })
    }

    fn slot(&self, id: [u8; 32]) -> Result<Arc<Slot>> {
        let mut cache = self.cache.lock().expect("token cache lock");
        if let Some((slot, last_access)) = cache.get_mut(&id) {
            *last_access = Instant::now();
            return Ok(slot.clone());
        }
        if cache.len() >= CACHE_SIZE {
            let idle = cache
                .iter()
                .filter(|(_, (slot, _))| Arc::strong_count(slot) == 1)
                .min_by_key(|(_, (_, last_access))| last_access)
                .map(|(key, _)| *key)
                .context("all token cache entries are busy")?;
            cache.remove(&idle);
        }
        let slot = Arc::new(Slot::default());
        cache.insert(id, (slot.clone(), Instant::now()));
        Ok(slot)
    }

    pub async fn mint(&self, key: &Key, scope: &Scope) -> Result<Token> {
        let pem = Zeroizing::new(
            tokio::fs::read(&key.private_key_file)
                .await
                .context("mint: read mounted private key")?,
        );
        let identity = serde_json::to_vec(&(
            key.app_id,
            key.install_id,
            &key.api_base_url,
            &key.private_key_file,
            scope,
        ))?;
        let mut hash = Sha256::new();
        hash.update(Sha256::digest(pem.as_slice()));
        hash.update(identity);
        let slot = self.slot(hash.finalize().into())?;
        if let Some(current) = slot.valid_token(SYNCHRONOUS_REFRESH_SECONDS) {
            if current.expires_at
                > Utc::now() + chrono::Duration::seconds(BACKGROUND_REFRESH_SECONDS)
            {
                return Ok(current);
            }
            if let Ok(guard) = slot.refresh.clone().try_lock_owned()
                && guard.is_none_or(|retry| retry <= Instant::now())
            {
                let broker = self.clone();
                let key = key.clone();
                let scope = scope.clone();
                tokio::spawn(async move {
                    let _ = broker.refresh(&slot, guard, &key, &scope, &pem).await;
                });
            }
            return Ok(current);
        }
        let guard = slot.refresh.clone().lock_owned().await;
        if let Some(token) = slot.valid_token(SYNCHRONOUS_REFRESH_SECONDS) {
            return Ok(token);
        }
        if guard.is_some_and(|retry| retry > Instant::now()) {
            return slot
                .valid_token(0)
                .context("installation token exchange cooling down");
        }
        self.refresh(&slot, guard, key, scope, &pem).await
    }

    async fn refresh(
        &self,
        slot: &Slot,
        mut guard: OwnedMutexGuard<Option<Instant>>,
        key: &Key,
        scope: &Scope,
        pem: &[u8],
    ) -> Result<Token> {
        let base = key.api_base()?.to_string();
        let endpoint = self
            .endpoints
            .lock()
            .expect("GitHub endpoint cache lock")
            .entry(base.clone())
            .or_default()
            .clone();
        let result = async {
            let token = tokio::time::timeout(self.timeout, async {
                let _permit = endpoint.exchange.acquire().await?;
                let attempt = endpoint.breaker.begin()?;
                let result = mint::exchange(
                    key,
                    &self.client,
                    scope,
                    pem,
                    Some(ExchangeObservation {
                        offset: &endpoint.clock_offset,
                        metrics: &self.metrics,
                        base: &base,
                    }),
                )
                .await;
                let succeeded = result.as_ref().map_or_else(
                    |error| {
                        error.is::<mint::PermissionsNotGranted>()
                            || error
                                .downcast_ref::<mint::GithubHttpError>()
                                .is_some_and(|error| {
                                    error.0.is_client_error()
                                        && error.0 != reqwest::StatusCode::TOO_MANY_REQUESTS
                                })
                    },
                    |_| true,
                );
                attempt.finish(succeeded);
                result
            })
            .await
            .context("mint: request timed out")??;
            ensure!(
                token.expires_at > Utc::now(),
                "mint: received an expired installation token"
            );
            Ok(token)
        }
        .await;
        let worst = self
            .endpoints
            .lock()
            .expect("GitHub endpoint cache lock")
            .values()
            .map(|endpoint| endpoint.breaker.state())
            .max()
            .unwrap_or_default();
        self.metrics.breaker(&base, endpoint.breaker.state(), worst);
        match result {
            Ok(token) => {
                *slot.current.lock().expect("token slot lock") = Some(token.clone());
                *guard = None;
                Ok(token)
            }
            Err(error) => {
                *guard = Some(Instant::now() + REFRESH_COOLDOWN);
                slot.valid_token(0).ok_or(error)
            }
        }
    }
}

impl Slot {
    fn valid_token(&self, minimum_seconds: i64) -> Option<Token> {
        self.current
            .lock()
            .expect("token slot lock")
            .as_ref()
            .filter(|token| {
                token.expires_at > Utc::now() + chrono::Duration::seconds(minimum_seconds)
            })
            .cloned()
    }
}
