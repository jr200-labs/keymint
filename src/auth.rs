use axum::http::HeaderMap;
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub fn client_ip(peer: IpAddr, headers: &HeaderMap, proxies: &[IpNet]) -> IpAddr {
    let trusted = |ip: IpAddr| proxies.iter().any(|proxy| proxy.contains(&ip));
    if !trusted(peer) {
        return peer;
    }
    let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
    for header in values.into_iter().rev() {
        let Ok(value) = header.to_str() else {
            return peer;
        };
        for hop in value.rsplit(',') {
            let Ok(ip) = hop.trim().parse::<IpAddr>() else {
                return peer;
            };
            if !trusted(ip) {
                return ip;
            }
        }
    }
    headers
        .get_all("x-real-ip")
        .iter()
        .next_back()
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
        .filter(|ip| !trusted(*ip))
        .unwrap_or(peer)
}

pub struct Limiter<K> {
    buckets: Mutex<HashMap<K, Bucket>>,
    rate: f64,
    burst: f64,
}
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl<K: Eq + Hash> Limiter<K> {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::default(),
            rate,
            burst,
        }
    }

    pub fn allows(&self, key: K) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        if buckets.len() >= 8192 && !buckets.contains_key(&key) {
            Self::prune(&mut buckets, now, self.rate, self.burst);
            if buckets.len() >= 8192 {
                return false;
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: self.burst,
            updated: now,
        });
        bucket.tokens = (bucket.tokens
            + now.duration_since(bucket.updated).as_secs_f64() * self.rate)
            .min(self.burst);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }

    pub fn sweep(&self) {
        Self::prune(
            &mut self.buckets.lock().expect("rate limiter lock"),
            Instant::now(),
            self.rate,
            self.burst,
        );
    }

    fn prune(buckets: &mut HashMap<K, Bucket>, now: Instant, rate: f64, burst: f64) {
        buckets.retain(|_, bucket| {
            bucket.tokens + now.duration_since(bucket.updated).as_secs_f64() * rate < burst
        });
    }
}

type ReviewSlot = Arc<tokio::sync::Mutex<Option<(Option<String>, Instant)>>>;

#[derive(Default)]
pub struct ReviewCache(Mutex<HashMap<[u8; 32], (ReviewSlot, Instant)>>);

impl ReviewCache {
    pub async fn review<F: std::future::Future<Output = anyhow::Result<Option<String>>>>(
        &self,
        bearer: &str,
        upstream: F,
        metrics: &crate::metrics::Metrics,
    ) -> anyhow::Result<Option<String>> {
        let id = Sha256::digest(bearer.as_bytes()).into();
        let slot = self.slot(id)?;
        let mut locked = slot.lock().await;
        if let Some((subject, expires)) = locked.as_ref()
            && *expires > Instant::now()
        {
            metrics.review_cache(true);
            return Ok(subject.clone());
        }
        metrics.review_cache(false);
        let result = upstream.await?;
        let ttl = Duration::from_secs(if result.is_some() { 60 } else { 15 });
        *locked = Some((result.clone(), Instant::now() + ttl));
        Ok(result)
    }

    fn slot(&self, id: [u8; 32]) -> anyhow::Result<ReviewSlot> {
        let mut slots = self.0.lock().expect("tokenreview cache lock");
        if slots.len() >= 4096 && !slots.contains_key(&id) {
            let oldest = slots
                .iter()
                .filter(|(_, (slot, _))| Arc::strong_count(slot) == 1)
                .min_by_key(|(_, (_, observed))| *observed)
                .map(|(id, _)| *id)
                .ok_or_else(|| anyhow::anyhow!("TokenReview cache is busy"))?;
            slots.remove(&oldest);
        }
        let (slot, access) = slots
            .entry(id)
            .or_insert_with(|| (ReviewSlot::default(), Instant::now()));
        *access = Instant::now();
        Ok(slot.clone())
    }
}
