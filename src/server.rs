use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router, body,
    extract::{ConnectInfo, MatchedPath, Path, Query, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::{Certificate, Client, Url};
use serde::Deserialize;
use serde_json::json;
use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::{Path as FilePath, PathBuf},
    sync::{Arc, RwLock as SyncRwLock},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore};
use zeroize::Zeroizing;

use crate::{
    auth::{self, Limiter, ReviewCache},
    breaker::Breaker,
    broker::InstallationBroker,
    cleanup::Recovery,
    config::Config,
    emergency::{self, CreateSession, Emergency, PublicSession},
    github::{self, Poll},
    journal::Journal,
    kube::{Credential, Issuer},
    metrics::Metrics,
    mint::{PermissionsNotGranted, Scope},
    release,
    telegram_relay::{self, Relay},
};

const SA_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SA_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

struct Broker {
    config: SyncRwLock<Arc<Config>>,
    policy_gate: tokio::sync::RwLock<()>,
    review_client: Client,
    review_endpoint: Url,
    sa_token: PathBuf,
    installation: InstallationBroker,
    metrics: Arc<Metrics>,
    review_slots: Semaphore,
    review_breaker: Breaker,
    reviewed: ReviewCache,
    pre_auth: Limiter<IpAddr>,
    post_auth: Limiter<String>,
    journal: Journal,
    recovery: Recovery,
    emergency: Emergency,
    telegram: Client,
}

#[derive(Deserialize)]
struct ReviewResponse {
    #[serde(default)]
    status: ReviewStatus,
}

#[derive(Default, Deserialize)]
struct ReviewStatus {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    user: ReviewUser,
}

#[derive(Default, Deserialize)]
struct ReviewUser {
    #[serde(default)]
    username: String,
}

impl Broker {
    fn from_cluster(config: Config, mint_timeout: Duration) -> Result<Self> {
        config.validate_service()?;
        let host =
            env::var("KUBERNETES_SERVICE_HOST").context("KUBERNETES_SERVICE_HOST is required")?;
        let port: u16 = env::var("KUBERNETES_SERVICE_PORT")
            .context("KUBERNETES_SERVICE_PORT is required")?
            .parse()
            .context("invalid KUBERNETES_SERVICE_PORT")?;
        let host = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
            _ => host,
        };
        ensure!(
            !host.is_empty() && !host.contains(['/', '@', '\\', '?', '#']),
            "invalid KUBERNETES_SERVICE_HOST"
        );
        let endpoint = Url::parse(&format!(
            "https://{host}:{port}/apis/authentication.k8s.io/v1/tokenreviews"
        ))
        .context("invalid Kubernetes API address")?;
        let ca = std::fs::read(SA_CA).context("read service account CA")?;
        let mut builder = Client::builder()
            .tls_built_in_root_certs(false)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10));
        let roots = Certificate::from_pem_bundle(&ca).context("parse service account CA")?;
        ensure!(!roots.is_empty(), "service account CA has no certificates");
        for root in roots {
            builder = builder.add_root_certificate(root);
        }
        std::fs::metadata(SA_TOKEN).context("stat service account token")?;
        let journal =
            Journal::open(&config.emergency_state_file).context("open emergency journal")?;
        let recovery =
            Recovery::open(&config.emergency_state_file).context("open emergency cleanup key")?;
        let emergency = Emergency::new(
            config.runtime_profiles()?,
            journal.clone(),
            config
                .runtime_passkeys()?
                .as_ref()
                .map(crate::passkeys::Passkeys::open)
                .transpose()?,
        )?;
        let metrics = Arc::new(Metrics::new()?);
        Ok(Self {
            journal,
            emergency,
            telegram: telegram_client()?,
            recovery,
            config: SyncRwLock::new(Arc::new(config)),
            policy_gate: tokio::sync::RwLock::new(()),
            review_client: builder.build()?,
            review_endpoint: endpoint,
            sa_token: SA_TOKEN.into(),
            installation: InstallationBroker::new(mint_timeout, metrics.clone())?,
            metrics,
            review_slots: Semaphore::new(100),
            review_breaker: Breaker::default(),
            reviewed: ReviewCache::default(),
            pre_auth: Limiter::new(10.0, 20.0),
            post_auth: Limiter::new(100.0, 200.0),
        })
    }

    fn config(&self) -> Arc<Config> {
        self.config.read().expect("configuration lock").clone()
    }

    async fn review(&self, bearer: &str) -> Result<Option<String>> {
        let attempt = self.review_breaker.begin()?;
        let result = self.upstream_review(bearer).await;
        let metric = match &result {
            Ok(Some(_)) => "accepted",
            Ok(None) => "rejected",
            Err(_) => "error",
        };
        self.metrics.review(metric);
        attempt.finish(result.is_ok());
        result
    }

    async fn upstream_review(&self, bearer: &str) -> Result<Option<String>> {
        let config = self.config();
        let _slot = self
            .review_slots
            .try_acquire()
            .context("TokenReview concurrency limit")?;
        let token = Zeroizing::new(
            tokio::fs::read_to_string(&self.sa_token)
                .await
                .context("read service account token")?,
        );
        let request = self
            .review_client
            .post(self.review_endpoint.clone())
            .bearer_auth(token.trim())
            .json(&json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": {"token": bearer, "audiences": config.expected_audiences},
            }));
        let mut response = crate::telemetry::send(request, "POST")
            .await?
            .error_for_status()?;
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                data.len() + chunk.len() <= 1 << 20,
                "TokenReview response exceeds 1 MiB"
            );
            data.extend_from_slice(&chunk);
        }
        let review: ReviewResponse = serde_json::from_slice(&data)?;
        let status = review.status;
        if status.authenticated
            && !status.user.username.is_empty()
            && status
                .audiences
                .iter()
                .any(|value| config.expected_audiences.contains(value))
        {
            Ok(Some(status.user.username))
        } else {
            Ok(None)
        }
    }
}

#[derive(clap::Args)]
pub struct Options {
    #[arg(long, default_value = "/etc/keymint/config.yaml")]
    config: PathBuf,
    #[arg(long, default_value = ":9999")]
    listen: String,
    #[arg(long, default_value = ":9100")]
    metrics_listen: String,
    #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
    mint_timeout: Duration,
    #[arg(long, default_value = "15s", value_parser = humantime::parse_duration)]
    shutdown_timeout: Duration,
    #[arg(long, default_value = "info", value_parser = ["disabled","panic","fatal","error","warn","info","debug","trace"])]
    log_level: String,
    #[arg(long)]
    log_human: bool,
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

pub async fn serve(options: Options) -> Result<()> {
    let filter = match options.log_level.as_str() {
        "disabled" | "panic" | "fatal" => tracing::level_filters::LevelFilter::OFF,
        "error" => tracing::level_filters::LevelFilter::ERROR,
        "warn" => tracing::level_filters::LevelFilter::WARN,
        "debug" => tracing::level_filters::LevelFilter::DEBUG,
        "trace" => tracing::level_filters::LevelFilter::TRACE,
        _ => tracing::level_filters::LevelFilter::INFO,
    };
    let telemetry = crate::telemetry::Telemetry::init(filter, options.log_human)?;
    let state = Arc::new(Broker::from_cluster(
        Config::load(Some(&options.config))?,
        options.mint_timeout,
    )?);
    state.recovery.check(&state.journal).await?;
    let listener = TcpListener::bind(listen_address(&options.listen))
        .await
        .context("listen for API requests")?;
    let metrics_listener = TcpListener::bind(listen_address(&options.metrics_listen))
        .await
        .context("listen for metrics requests")?;
    let tls = if let (Some(cert), Some(key)) = (options.tls_cert, options.tls_key) {
        Some(
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .context("load API TLS certificate")?,
        )
    } else {
        None
    };
    let metrics = state.metrics.clone();
    if tokio::time::timeout(Duration::from_secs(15), recover(&state))
        .await
        .map_or(true, |result| result.is_err())
    {
        eprintln!("emergency credential recovery failed; cleanup will retry");
    }
    let config_path = options.config;
    let reload_state = state.clone();
    let reload = tokio::spawn(async move { watch_configuration(reload_state, config_path).await });
    let worker = state.clone();
    let janitor = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _policy = worker.policy_gate.read().await;
            let retention = worker.config().journal_retention().ok().flatten();
            worker.pre_auth.sweep();
            worker.post_auth.sweep();
            if let Some(retention) = retention
                && worker.journal.prune(retention).await.is_err()
            {
                eprintln!("emergency journal pruning failed");
            }
            if worker.emergency.prune().await.is_err() {
                eprintln!("emergency session pruning failed");
            }
            let cleanup = async {
                for (subject, id) in worker.emergency.pending().await {
                    if revoke_session(&worker, &subject, &id).await.is_err() {
                        eprintln!("emergency session revocation pending");
                    }
                }
                recover(&worker).await
            };
            if tokio::time::timeout(Duration::from_secs(30), cleanup)
                .await
                .map_or(true, |result| result.is_err())
            {
                eprintln!("emergency credential cleanup failed");
            }
        }
    });
    let router = routes(state.clone()).layer(axum::middleware::from_fn_with_state(
        metrics.clone(),
        Metrics::observe,
    ));
    let handle = axum_server::Handle::new();
    let metrics_handle = axum_server::Handle::new();
    let api = async {
        match tls {
            Some(tls) => {
                axum_server::from_tcp_rustls(listener.into_std()?, tls)?
                    .handle(handle.clone())
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
            None => {
                axum_server::from_tcp(listener.into_std()?)?
                    .handle(handle.clone())
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
        }
    };
    let metrics_api = axum_server::from_tcp(metrics_listener.into_std()?)?
        .handle(metrics_handle.clone())
        .serve(
            Router::new()
                .route("/metrics", get(Metrics::handle))
                .with_state(metrics)
                .into_make_service(),
        );
    tokio::pin!(api, metrics_api);
    let result = tokio::select! {
        result = &mut api => result.context("serve API requests"),
        result = &mut metrics_api => result.context("serve metrics requests"),
        _ = shutdown_signal() => {
            handle.graceful_shutdown(Some(options.shutdown_timeout));
            metrics_handle.graceful_shutdown(Some(options.shutdown_timeout));
            let (api, metrics) = tokio::join!(api, metrics_api);
            api.and(metrics).context("graceful HTTP shutdown")
        }
    };
    janitor.abort();
    reload.abort();
    let _ = tokio::join!(janitor, reload);
    let cleanup = async {
        state.emergency.reload(Default::default(), &[]).await;
        for (subject, id) in state.emergency.pending().await {
            if revoke_session(&state, &subject, &id).await.is_err() {
                tracing::error!("emergency session revocation pending at shutdown");
            }
        }
        recover(&state).await
    };
    if tokio::time::timeout(options.shutdown_timeout, cleanup)
        .await
        .map_or(true, |result| result.is_err())
    {
        tracing::error!("emergency cleanup incomplete at shutdown");
    }
    telemetry.shutdown(options.shutdown_timeout).await;
    result
}

async fn watch_configuration(broker: Arc<Broker>, path: PathBuf) {
    use sha2::{Digest, Sha256};
    let mut observed = None;
    loop {
        tokio::time::sleep(Duration::from_millis(600)).await;
        let Ok(contents) = tokio::fs::read(&path).await.map(Zeroizing::new) else {
            continue;
        };
        let digest = Sha256::digest(&*contents);
        if observed == Some(digest) {
            continue;
        }
        observed = Some(digest);
        if let Err(error) = reload_configuration(&broker, &contents).await {
            tracing::error!(%error, "configuration reload failed");
        }
    }
}

async fn reload_configuration(broker: &Broker, contents: &[u8]) -> Result<()> {
    let started = std::time::Instant::now();
    let result = apply_configuration(broker, contents).await;
    broker
        .metrics
        .operation("config_reload", result.is_ok(), started);
    result
}

async fn apply_configuration(broker: &Broker, contents: &[u8]) -> Result<()> {
    let config = Config::parse(contents)?;
    config.validate_service()?;
    let definitions = config.runtime_profiles()?;
    let _policy = broker.policy_gate.write().await;
    config.validate_reload_from(&broker.config())?;
    broker
        .emergency
        .reload(definitions, &config.allowlist)
        .await;
    *broker.config.write().expect("configuration lock") = Arc::new(config);
    tracing::info!("configuration reloaded");
    Ok(())
}

fn listen_address(address: &str) -> String {
    if address.starts_with(':') {
        format!("0.0.0.0{address}")
    } else {
        address.into()
    }
}

fn routes(state: Arc<Broker>) -> Router {
    Router::new()
        .route("/livez", get(|| async { "ok" }))
        .route("/readyz", get(readiness))
        .route("/healthz", get(readiness))
        .route("/token/{key}", post(mint_handler))
        .route("/emergency/events", get(emergency_events))
        .route("/emergency/profiles", get(emergency_profiles))
        .route("/emergency/sessions", post(emergency_create))
        .route(
            "/emergency/sessions/{id}",
            get(emergency_get).delete(emergency_revoke),
        )
        .route("/emergency/sessions/{id}/verify", post(emergency_verify))
        .route(
            "/emergency/sessions/{id}/credential",
            post(emergency_credential),
        )
        .route(
            "/emergency/sessions/{id}/seal-release-key",
            post(seal_release),
        )
        .route(
            "/emergency/sessions/{id}/redeem-approval",
            post(redeem_approval),
        )
        .route(
            "/emergency/passkeys/ceremonies/{token}",
            get(passkey_options).post(passkey_verify),
        )
        .route("/emergency/passkeys/enrollments", post(passkey_enroll))
        .route("/telegram-enrollments/{relay}", post(telegram_approval))
        .route(
            "/telegram-enrollments/{relay}/{id}/{action}",
            get(telegram_enrollment).post(telegram_enrollment),
        )
        .route(
            "/telegram-relays/{relay}/wrapping-key",
            get(telegram_wrapping_key),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            pre_auth,
        ))
        .with_state(state)
}

async fn recover(state: &Broker) -> Result<()> {
    let result = state
        .recovery
        .drain(
            &state.journal,
            &state.review_client,
            &state.review_endpoint,
            &state.sa_token,
        )
        .await;
    let measured = state
        .recovery
        .collect_metrics(&state.journal, &state.metrics)
        .await;
    result.and(measured)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn readiness() -> Result<&'static str, ApiError> {
    for (file, message) in [(SA_TOKEN, "sa token missing"), (SA_CA, "sa ca missing")] {
        if tokio::fs::metadata(FilePath::new(file)).await.is_err() {
            return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, message.into()));
        }
    }
    Ok("ready")
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

async fn pre_auth(
    State(broker): State<Arc<Broker>>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let _policy = broker.policy_gate.read().await;
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    if !matches!(route, Some("/livez" | "/readyz" | "/healthz"))
        && let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>()
    {
        let ip = auth::client_ip(
            peer.ip(),
            request.headers(),
            &broker.config().trusted_proxies,
        );
        if !broker.pre_auth.allows(ip) {
            return ApiError(StatusCode::TOO_MANY_REQUESTS, "too many requests".into())
                .into_response();
        }
    }
    next.run(request).await
}

async fn authenticate(
    broker: &Broker,
    headers: &axum::http::HeaderMap,
) -> Result<String, ApiError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|header| header.split_once(' '))
        .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty())
        .map(|(_, token)| token.trim())
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "missing or malformed Authorization header".into(),
            )
        })?;
    let subject = broker
        .reviewed
        .review(bearer, broker.review(bearer), &broker.metrics)
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "kubernetes tokenreview unavailable; retry".into(),
            )
        })?
        .ok_or_else(|| {
            ApiError(
                StatusCode::UNAUTHORIZED,
                "tokenreview rejected the bearer token".into(),
            )
        })?;
    if !broker.post_auth.allows(subject.clone()) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests".into(),
        ));
    }
    Ok(subject)
}

#[derive(Deserialize)]
struct EventQuery {
    #[serde(default)]
    after: String,
    wait: Option<String>,
}

async fn emergency_events(
    State(broker): State<Arc<Broker>>,
    Query(query): Query<EventQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let result = async {
        let subject = authenticate(&broker, &headers).await?;
        let wait = match query.wait.as_deref().filter(|wait| !wait.is_empty()) {
            None => Duration::from_secs(30),
            Some(wait) => humantime::parse_duration(wait).map_err(|_| {
                ApiError(
                    StatusCode::BAD_REQUEST,
                    "wait must be a non-negative duration".into(),
                )
            })?,
        };
        let page = broker
            .journal
            .watch(subject, query.after, wait)
            .await
            .map_err(|_| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "watch emergency events".into(),
                )
            })?;
        Ok::<_, ApiError>(Json(page))
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

async fn emergency_profiles(
    State(broker): State<Arc<Broker>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let subject = authenticate(&broker, &headers).await?;
    let profiles = broker
        .emergency
        .profiles(&broker.config().allowlist, &subject)
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "list emergency profiles".into(),
            )
        })?;
    Ok(Json(json!({"profiles": profiles})))
}

async fn emergency_request<T: serde::de::DeserializeOwned>(
    request: Request,
    limit: usize,
) -> Result<T, ApiError> {
    let bytes = body::to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid request".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid request".into()))
}

async fn emergency_create(
    State(broker): State<Arc<Broker>>,
    request: Request,
) -> Result<Json<PublicSession>, ApiError> {
    let subject = authenticate(&broker, request.headers()).await?;
    let input: CreateSession = emergency_request(request, 32 << 10).await?;
    broker
        .emergency
        .create(&broker.config().allowlist, subject, input)
        .await
        .map(Json)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))
}

async fn emergency_get(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<PublicSession>, ApiError> {
    let subject = authenticate(&broker, &headers).await?;
    let task = tokio::spawn(async move {
        let mut session = broker.emergency.owned(&subject, &id).await?;
        if session.expire_if_due(&broker.journal)? {
            broker
                .recovery
                .revoke_record(
                    &broker.journal,
                    &id,
                    &broker.review_client,
                    &broker.review_endpoint,
                    &broker.sa_token,
                )
                .await?;
        }

        if session
            .device
            .as_ref()
            .is_some_and(|device| device.next_poll <= chrono::Utc::now())
            && session.expires_at() > chrono::Utc::now()
        {
            poll_github(&broker, &mut session).await?;
        }
        Ok::<_, anyhow::Error>(session.public())
    });
    task.await
        .ok()
        .and_then(Result::ok)
        .map(Json)
        .ok_or_else(|| {
            ApiError(
                StatusCode::NOT_FOUND,
                "emergency session is unavailable".into(),
            )
        })
}

async fn poll_github(broker: &Broker, session: &mut emergency::Session) -> Result<()> {
    let identity = session.definition.identity()?;
    let client = broker.emergency.github_client();
    let poll = session
        .device
        .as_mut()
        .context("device login is unavailable")?
        .poll(client, &identity)
        .await?;
    match poll {
        Poll::Pending => Ok(()),
        Poll::Expired | Poll::Rejected => {
            session.device = None;
            session.publish(&broker.journal, false, matches!(poll, Poll::Expired))?;
            anyhow::bail!("GitHub device flow did not issue a token");
        }
        Poll::Token(token, granted) => {
            session.device = None;
            if let Err(error) = broker.recovery.reserve_oauth(
                &broker.journal,
                session.id(),
                &identity,
                &token,
                &session.definition.namespace,
                session.expires_at(),
            ) {
                let _ = broker
                    .recovery
                    .revoke_oauth(&identity.id, &identity.secret, &token, "")
                    .await;
                let _ = session.publish(&broker.journal, false, false);
                return Err(error);
            }
            let activation = async {
                ensure!(
                    !session.github() || granted == session.expected_scopes(),
                    "GitHub granted an unexpected OAuth scope"
                );
                github::verify_user(client, &token, &identity.users).await?;
                ensure!(
                    session.expires_at() > chrono::Utc::now(),
                    "session expired during authentication"
                );
                session.publish(&broker.journal, true, false)
            }
            .await;
            if let Err(error) = activation {
                let _ = session.publish(&broker.journal, false, false);
                let _ = broker
                    .recovery
                    .revoke_record(
                        &broker.journal,
                        session.id(),
                        &broker.review_client,
                        &broker.review_endpoint,
                        &broker.sa_token,
                    )
                    .await;
                return Err(error);
            }
            session.access_token = Some(token);
            Ok(())
        }
    }
}

async fn emergency_verify(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Json<PublicSession>, ApiError> {
    #[derive(Deserialize)]
    struct Input {
        code: String,
    }
    let subject = authenticate(&broker, request.headers()).await?;
    let input: Input = emergency_request(request, 4096).await?;
    broker
        .emergency
        .verify(&subject, &id, &input.code)
        .await
        .map(Json)
        .map_err(|error| ApiError(StatusCode::UNAUTHORIZED, error.to_string()))
}

async fn emergency_credential(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], Json<Credential>), ApiError> {
    let subject = authenticate(&broker, &headers).await?;
    let mut session = broker
        .emergency
        .owned(&subject, &id)
        .await
        .map_err(|error| ApiError(StatusCode::CONFLICT, error.to_string()))?;
    if !session.active() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "emergency session is not active".into(),
        ));
    }
    if session.approval() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "session cannot issue credentials".into(),
        ));
    }
    if session.github() {
        let access = session.access_token.as_ref().ok_or_else(|| {
            ApiError(
                StatusCode::CONFLICT,
                "emergency session is not active".into(),
            )
        })?;
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(Credential::github(access.to_string(), session.expires_at())),
        ));
    }
    let task = tokio::spawn(async move {
        if session.bound_secret.is_none() {
            let random = emergency::random_id(18)?;
            let secret = format!("keymint-emergency-{}", hex_secret_name(&random));
            broker.recovery.reserve_kubernetes(
                &broker.journal,
                session.id(),
                &session.definition.namespace,
                &secret,
                session.expires_at(),
            )?;
            session.bound_secret = Some(secret);
        }
        let issuer = Issuer {
            client: &broker.review_client,
            cluster: &broker.review_endpoint,
            sa_token: &broker.sa_token,
        };
        let credential = issuer
            .issue(
                &session.definition.namespace,
                &session.definition.service_account,
                session
                    .bound_secret
                    .as_deref()
                    .context("missing credential binding")?,
                session.expires_at(),
            )
            .await?;
        ensure!(session.active(), "emergency session is no longer active");
        Ok::<_, anyhow::Error>(credential)
    });
    let credential = task.await.ok().and_then(Result::ok).ok_or_else(|| {
        ApiError(
            StatusCode::CONFLICT,
            "Kubernetes emergency credential issuance failed".into(),
        )
    })?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(credential)))
}

fn hex_secret_name(random: &str) -> String {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(&Sha256::digest(random.as_bytes())[..12])
}

async fn emergency_revoke(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, ApiError> {
    let subject = authenticate(&broker, &headers).await?;
    revoke_session(&broker, &subject, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_session(broker: &Broker, subject: &str, id: &str) -> Result<(), ApiError> {
    let mut session = broker
        .emergency
        .owned(subject, id)
        .await
        .map_err(|error| ApiError(StatusCode::NOT_FOUND, error.to_string()))?;
    let unavailable = || {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency session revocation unavailable".into(),
        )
    };
    session
        .begin_revoke(&broker.journal)
        .map_err(|_| unavailable())?;
    broker
        .recovery
        .revoke_record(
            &broker.journal,
            id,
            &broker.review_client,
            &broker.review_endpoint,
            &broker.sa_token,
        )
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::BAD_GATEWAY,
                "emergency credential revocation is pending".into(),
            )
        })?;
    session.bound_secret = None;
    session.access_token = None;
    session.device = None;
    session
        .finish_revoke(&broker.journal)
        .map_err(|_| unavailable())?;
    Ok(())
}

async fn seal_release(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    request: Request,
) -> Result<
    (
        [(header::HeaderName, &'static str); 1],
        Json<release::Sealed>,
    ),
    ApiError,
> {
    #[derive(Deserialize)]
    struct Input {
        #[serde(flatten)]
        target: release::Target,
        #[serde(default)]
        destination_key_id: String,
        #[serde(default)]
        destination_public_key: String,
    }
    let config = broker.config();
    let subject = authenticate(&broker, request.headers()).await?;
    let session_inactive = || {
        ApiError(
            StatusCode::CONFLICT,
            "emergency session is not active".into(),
        )
    };
    let session = broker
        .emergency
        .owned(&subject, &id)
        .await
        .map_err(|_| session_inactive())?;
    if !session.active() || session.approval() {
        return Err(session_inactive());
    }
    let input: Input = emergency_request(request, 4096).await?;
    input.target.validate().map_err(|_| {
        ApiError(
            StatusCode::BAD_REQUEST,
            "invalid release-key sealing target".into(),
        )
    })?;
    let repo = input.target.repository();
    let configured = config
        .release_keys
        .iter()
        .find(|(name, key)| {
            key.repositories.contains(&repo)
                && key.scopes().contains(&input.target.secret_scope)
                && config
                    .allowlist
                    .iter()
                    .any(|entry| entry.subject == subject && entry.release_keys.contains(name))
        })
        .map(|(_, key)| key)
        .ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                "release signing key is unavailable".into(),
            )
        })?;
    let lookup_failed = || {
        ApiError(
            StatusCode::BAD_GATEWAY,
            "Actions encryption key could not be resolved".into(),
        )
    };
    let installation = config
        .keys
        .get(&configured.github_key)
        .ok_or_else(lookup_failed)?;
    let base = installation.api_base().map_err(|_| lookup_failed())?;
    let user = if input.target.secret_scope == release::Scope::Organization {
        if !session.github()
            || !session
                .expected_scopes()
                .iter()
                .any(|scope| scope == "admin:org")
        {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "GitHub session must allow admin:org for organization secrets".into(),
            ));
        }
        if session.definition.api_base().ok().as_ref() != Some(&base) {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "GitHub session belongs to a different API endpoint".into(),
            ));
        }
        let access = session.access_token.as_ref().ok_or_else(session_inactive)?;
        Some(Zeroizing::new(access.to_string()))
    } else {
        None
    };
    drop(session);
    let token = if let Some(user) = user {
        user
    } else {
        Zeroizing::new(
            broker
                .installation
                .mint(
                    installation,
                    &Scope {
                        repositories: vec![input.target.github_repository.clone()],
                        permissions: [("secrets".into(), "read".into())].into_iter().collect(),
                    },
                )
                .await
                .map_err(|_| lookup_failed())?
                .token,
        )
    };
    let destination = release::resolve(
        broker.emergency.github_client(),
        base,
        &token,
        &input.target,
    )
    .await
    .map_err(|_| lookup_failed())?;
    if (!input.destination_key_id.is_empty() && input.destination_key_id != destination.key_id)
        || (!input.destination_public_key.is_empty()
            && input.destination_public_key != destination.public_key)
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "destination does not match the selected Actions encryption key".into(),
        ));
    }
    let session = broker
        .emergency
        .owned(&subject, &id)
        .await
        .map_err(|_| session_inactive())?;
    if !session.active() || session.approval() {
        return Err(session_inactive());
    }
    let sealed = configured.seal(input.target, destination).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "release signing key could not be sealed".into(),
        )
    })?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(sealed)))
}

async fn redeem_approval(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    request: Request,
) -> Result<StatusCode, ApiError> {
    #[derive(Deserialize)]
    struct Input {
        approval_digest: String,
    }
    let subject = authenticate(&broker, request.headers()).await?;
    let input: Input = emergency_request(request, 1024)
        .await
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid approval request".into()))?;
    let unavailable = || ApiError(StatusCode::CONFLICT, "approval is unavailable".into());
    let mut session = broker
        .emergency
        .owned(&subject, &id)
        .await
        .map_err(|_| unavailable())?;
    session
        .redeem(&broker.journal, &input.approval_digest)
        .map_err(|_| unavailable())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn passkey_options(
    State(broker): State<Arc<Broker>>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let result = async {
        let subject = authenticate(&broker, &headers).await?;
        let value = broker
            .emergency
            .ceremony_options(&subject, &token)
            .await
            .map_err(|_| {
                ApiError(
                    StatusCode::NOT_FOUND,
                    "passkey ceremony not found or expired".into(),
                )
            })?;
        Ok::<_, ApiError>(Json(value))
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

async fn passkey_verify(
    State(broker): State<Arc<Broker>>,
    Path(token): Path<String>,
    request: Request,
) -> Response {
    let result = async {
        let subject = authenticate(&broker, request.headers()).await?;
        let mut values = request.headers().get_all("X-Padd-Approval-Duration").iter();
        let minutes = if let Some(value) = values.next() {
            let parsed = value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<i64>().ok());
            if values.next().is_some() || parsed.is_none() {
                return Err(ApiError(
                    StatusCode::UNAUTHORIZED,
                    "invalid REST approval duration".into(),
                ));
            }
            parsed
        } else {
            None
        };
        let data = body::to_bytes(request.into_body(), 64 << 10)
            .await
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid passkey response".into()))?;
        broker
            .emergency
            .verify_passkey(&subject, &token, &data, minutes)
            .await
            .map_err(|_| {
                ApiError(
                    StatusCode::UNAUTHORIZED,
                    "passkey verification failed".into(),
                )
            })?;
        Ok::<_, ApiError>(Json(json!({"state":"complete"})))
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

async fn passkey_enroll(State(broker): State<Arc<Broker>>, request: Request) -> Response {
    #[derive(Deserialize)]
    struct Input {
        proof_session_id: String,
        #[serde(default)]
        label: String,
    }
    let result = async {
        let subject = authenticate(&broker, request.headers()).await?;
        let input: Input = emergency_request(request, 4096).await?;
        let value = broker
            .emergency
            .begin_enrollment(&subject, &input.proof_session_id, &input.label)
            .await
            .map_err(|error| ApiError(StatusCode::FORBIDDEN, error.to_string()))?;
        Ok::<_, ApiError>(Json(value))
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

fn telegram_client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()?)
}

fn operator_relay<'a>(
    config: &'a Config,
    subject: &str,
    name: &str,
) -> Result<&'a Relay, ApiError> {
    config
        .telegram_relays
        .get(name)
        .filter(|relay| relay.operator_subject == subject)
        .ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                "Telegram enrollment is unavailable".into(),
            )
        })
}

async fn telegram_approval(
    State(broker): State<Arc<Broker>>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let result = async {
        let config = broker.config();
        let subject = authenticate(&broker, &headers).await?;
        let relay = operator_relay(&config, &subject, &name)?;
        let (digest, label) = relay.approval(&name);
        let request = CreateSession {
            profile: relay.approval_profile.clone(),
            ttl_seconds: Some(300),
            scopes: Vec::new(),
            approval_digest: digest,
            approval_label: label,
        };
        broker
            .emergency
            .create(&config.allowlist, subject, request)
            .await
            .map(Json)
            .map_err(|_| {
                ApiError(
                    StatusCode::FORBIDDEN,
                    "Telegram enrollment approval is unavailable".into(),
                )
            })
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

async fn telegram_enrollment(
    State(broker): State<Arc<Broker>>,
    Path((name, id, action)): Path<(String, String, String)>,
    request: Request,
) -> Response {
    let result = async {
        let config = broker.config();
        let subject = authenticate(&broker, request.headers()).await?;
        let relay = operator_relay(&config, &subject, &name)?;
        let method = request.method().as_str();
        if !telegram_relay::valid_id(&id)
            || !matches!(
                (method, action.as_str()),
                ("GET", "status" | "qr") | ("POST", "start" | "commit" | "cancel" | "password")
            )
        {
            return Err(ApiError(
                StatusCode::NOT_FOUND,
                "Telegram enrollment action is unavailable".into(),
            ));
        }
        let terminal = request
            .headers()
            .get(header::ACCEPT)
            .is_some_and(|value| value == "text/plain");
        let password = if action == "password" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Password {
                password: String,
            }
            let input: Password = emergency_request(request, 4096).await.map_err(|_| {
                ApiError(
                    StatusCode::BAD_REQUEST,
                    "Telegram password is required".into(),
                )
            })?;
            let password = Zeroizing::new(input.password);
            if password.is_empty() || password.len() > 1024 {
                return Err(ApiError(
                    StatusCode::BAD_REQUEST,
                    "Telegram password is required".into(),
                ));
            }
            password
        } else {
            Zeroizing::new(String::new())
        };
        let (digest, label) = relay.approval(&name);
        let required = || {
            ApiError(
                StatusCode::FORBIDDEN,
                "active passkey approval for this Telegram relay is required".into(),
            )
        };
        let mut session = broker
            .emergency
            .owned(&subject, &id)
            .await
            .map_err(|_| required())?;
        if !session.approval_matches(&relay.approval_profile, &digest, &label) {
            return Err(required());
        }
        if !session.approval_used() {
            let start = || {
                ApiError(
                    StatusCode::CONFLICT,
                    "start the approved Telegram enrollment first".into(),
                )
            };
            if action != "start" {
                return Err(start());
            }
            session
                .redeem(&broker.journal, &digest)
                .map_err(|_| start())?;
        }
        let status = relay
            .call(
                &broker.telegram,
                &telegram_relay::Action {
                    action: if action == "qr" { "status" } else { &action },
                    id: &id,
                    owner_id: relay.owner_id,
                    expires_at: session.expires_at(),
                    password: &password,
                },
            )
            .await
            .map_err(|telegram_relay::Failure(code, message)| ApiError(code, message.into()))?;
        if !session.active() {
            return Err(required());
        }
        if action == "qr" {
            let (content_type, data) = status
                .qr(terminal)
                .map_err(|telegram_relay::Failure(code, message)| ApiError(code, message.into()))?;
            return Ok(([(header::CONTENT_TYPE, content_type)], data).into_response());
        }
        Ok::<_, ApiError>(Json(status).into_response())
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

async fn telegram_wrapping_key(
    State(broker): State<Arc<Broker>>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let result = async {
        let config = broker.config();
        let subject = authenticate(&broker, &headers).await?;
        let relay = config
            .telegram_relays
            .get(&name)
            .filter(|relay| relay.relay_subject == subject)
            .ok_or_else(|| {
                ApiError(
                    StatusCode::FORBIDDEN,
                    "Telegram wrapping key is unavailable".into(),
                )
            })?;
        let key = relay.wrapping_key().map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Telegram wrapping key is unavailable".into(),
            )
        })?;
        Ok::<_, ApiError>((
            [(header::CONTENT_TYPE, "application/octet-stream")],
            key.to_vec(),
        ))
    }
    .await;
    (
        [(header::CACHE_CONTROL, "no-store")],
        result.into_response(),
    )
        .into_response()
}

async fn mint_handler(
    State(broker): State<Arc<Broker>>,
    Path(key): Path<String>,
    request: Request,
) -> Response {
    let _in_flight = broker.metrics.mint_started();
    let started = std::time::Instant::now();
    let config = broker.config();
    let label = if config.keys.contains_key(&key) {
        key.clone()
    } else {
        "_unknown".into()
    };
    let result = mint_request(broker.clone(), key, request)
        .await
        .into_response();
    broker
        .metrics
        .mint_outcome(&label, result.status(), started);
    result
}

async fn mint_request(
    broker: Arc<Broker>,
    key_name: String,
    request: Request,
) -> Result<Response, ApiError> {
    let config = broker.config();
    let started = std::time::Instant::now();
    let subject = authenticate(&broker, request.headers()).await;
    broker
        .metrics
        .operation("authenticate", subject.is_ok(), started);
    let subject = subject?;
    let policy = config
        .allowlist
        .iter()
        .find(|entry| entry.subject == subject && entry.keys.contains(&key_name))
        .ok_or_else(|| {
            ApiError(
                StatusCode::FORBIDDEN,
                format!("subject {subject:?} not permitted to mint key {key_name:?}"),
            )
        })?;
    let key = config
        .keys
        .get(&key_name)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("key {key_name:?} not found")))?;
    let data = body::to_bytes(request.into_body(), 8192)
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "token scope is too large".into(),
            )
        })?;
    let mut scope = if data.iter().all(u8::is_ascii_whitespace) {
        Scope::default()
    } else {
        serde_json::from_slice::<Option<Scope>>(&data)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid token scope".into()))?
            .unwrap_or_default()
    };
    scope
        .validate()
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string()))?;
    if !policy.allows_scope(&scope) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "token scope is outside the workload allowlist".into(),
        ));
    }
    match broker.installation.mint(key, &scope).await {
        Ok(token) => {
            use sha2::{Digest, Sha256};
            let fingerprint =
                data_encoding::HEXLOWER.encode(&Sha256::digest(token.token.as_bytes()));
            tracing::info!(key = key_name, %subject, token_fingerprint = fingerprint, expires_at = %token.expires_at, "minted");
            Ok(Json(token).into_response())
        }
        Err(error) if error.is::<PermissionsNotGranted>() => {
            let permissions: Vec<_> = scope
                .permissions
                .iter()
                .map(|(name, access)| format!("{name}={access}"))
                .collect();
            let requested = if permissions.is_empty() {
                String::new()
            } else {
                format!(" ({})", permissions.join(", "))
            };
            let message = format!(
                "GitHub rejected the requested token permissions for key {key_name:?}{requested}: the installation has not granted one or more requested permissions. Update the GitHub App permissions and approve the installation update, or request a narrower permission scope."
            );
            Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error":message,"code":"github_permissions_not_granted"
                })),
            )
                .into_response())
        }
        Err(_) => Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "mint failed".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::delete;
    use rusqlite::Connection;
    use serde_json::Value;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn totp_authorizes_only_the_owner_and_binds_credential_to_durable_cleanup() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let token_file = dir.path().join("sa-token");
        std::fs::write(&token_file, "broker-token")?;
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let secret_file = dir.path().join("totp");
        std::fs::write(&secret_file, secret)?;
        let db_path = dir.path().join("emergency.db");
        let config_path = dir.path().join("keymint.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&json!({
                "keys": {"app":{"app_id":1,"install_id":1,"private_key_file":"unused"}},
                "expected_audiences":["keymint"],
                "allowlist":[{"subject":"owner","emergency_profiles":["fixture"]}],
                "emergency_state_file": db_path,
                "emergency_profiles":{"fixture":{"provider":"kubernetes","namespace":"fixture",
                    "service_account":"emergency","totp_secret_file":secret_file}},
            }))?,
        )?;
        let revoked = Arc::new(AtomicBool::new(false));
        let first_revocation = Arc::new(AtomicBool::new(true));
        let kube = Router::new()
            .route("/apis/authentication.k8s.io/v1/tokenreviews", post(|Json(input): Json<Value>| async move {
                let subject = input["spec"]["token"].as_str().unwrap_or_default();
                let audience = if subject == "wrong-audience" { "other" } else { "keymint" };
                Json(json!({"status":{"authenticated":true,"audiences":[audience],"user":{"username":subject}}}))
            }))
            .route("/api/v1/namespaces/fixture/secrets", post({
                let db_path = db_path.clone();
                move || async move {
                    let conn = Connection::open(db_path).unwrap();
                    let count: i64 = conn.query_row("SELECT count(*) FROM emergency_cleanup", [], |row| row.get(0)).unwrap();
                    if count == 1 { StatusCode::CREATED } else { StatusCode::INTERNAL_SERVER_ERROR }
                }
            }))
            .route("/api/v1/namespaces/fixture/secrets/{secret}",
                get(|| async { Json(json!({"metadata":{"uid":"bound-uid"}})) }).merge(delete({
                    let revoked = revoked.clone();
                                let first_revocation = first_revocation.clone();
                    move || async move {
                        if first_revocation.swap(false, Ordering::Relaxed) {
                                        return StatusCode::BAD_GATEWAY;
                                    }
                                    revoked.store(true, Ordering::Relaxed);
                        StatusCode::NO_CONTENT
                    }
                })))
            .route("/api/v1/namespaces/fixture/serviceaccounts/emergency/token", post(|Json(input): Json<Value>| async move {
                assert_eq!(input["spec"]["boundObjectRef"]["uid"], "bound-uid");
                Json(json!({"status":{"token":"test-issued-token","expirationTimestamp": (chrono::Utc::now() + chrono::Duration::hours(1))}}))
            }));
        let upstream = TcpListener::bind("127.0.0.1:0").await?;
        let review_endpoint = Url::parse(&format!(
            "http://{}/apis/authentication.k8s.io/v1/tokenreviews",
            upstream.local_addr()?
        ))?;
        let kube_task = tokio::spawn(async move { axum::serve(upstream, kube).await });
        let config = Config::load(Some(&config_path))?;
        let journal = Journal::open(&db_path)?;
        let emergency = Emergency::new(
            config.runtime_profiles()?,
            journal.clone(),
            config
                .runtime_passkeys()?
                .as_ref()
                .map(crate::passkeys::Passkeys::open)
                .transpose()?,
        )?;
        let metrics = Arc::new(Metrics::new()?);
        let state = Arc::new(Broker {
            config: SyncRwLock::new(Arc::new(config)),
            policy_gate: tokio::sync::RwLock::new(()),
            journal: journal.clone(),
            emergency,
            telegram: telegram_client()?,
            recovery: Recovery::open(&db_path)?,
            review_client: Client::new(),
            review_endpoint,
            sa_token: token_file,
            installation: InstallationBroker::new(Duration::from_secs(5), metrics.clone())?,
            metrics,
            review_slots: Semaphore::new(10),
            review_breaker: Breaker::default(),
            reviewed: ReviewCache::default(),
            pre_auth: Limiter::new(10.0, 20.0),
            post_auth: Limiter::new(100.0, 200.0),
        });
        let api = TcpListener::bind("127.0.0.1:0").await?;
        let root = format!("http://{}/emergency", api.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(api, routes(state)).await });
        let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
        let denied = client
            .get(format!("{root}/profiles"))
            .bearer_auth("wrong-audience")
            .send()
            .await?;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let session: Value = client
            .post(format!("{root}/sessions"))
            .bearer_auth("owner")
            .json(&json!({"profile":"fixture","ttl_seconds":120}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let id = session["id"].as_str().unwrap();
        let endpoint = format!("{root}/sessions/{id}");
        let hidden = client
            .get(&endpoint)
            .bearer_auth("another-owner")
            .send()
            .await?;
        assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
        let before = client
            .post(format!("{endpoint}/credential"))
            .bearer_auth("owner")
            .send()
            .await?;
        assert_eq!(before.status(), StatusCode::CONFLICT);
        let code = emergency::test_totp_code(secret)?;
        client
            .post(format!("{endpoint}/verify"))
            .bearer_auth("owner")
            .json(&json!({"code":code}))
            .send()
            .await?
            .error_for_status()?;
        let issued: Value = client
            .post(format!("{endpoint}/credential"))
            .bearer_auth("owner")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(issued["token"], "test-issued-token");
        assert_eq!(issued["expires_at"], session["expires_at"]);
        let failed = client.delete(&endpoint).bearer_auth("owner").send().await?;
        assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
        let pending = client
            .post(format!("{endpoint}/credential"))
            .bearer_auth("owner")
            .send()
            .await?;
        assert_eq!(pending.status(), StatusCode::CONFLICT);
        let retained: i64 = Connection::open(&db_path)?.query_row(
            "SELECT count(*) FROM emergency_cleanup",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(retained, 1);
        let revoked_response = client.delete(&endpoint).bearer_auth("owner").send().await?;
        assert_eq!(revoked_response.status(), StatusCode::NO_CONTENT);
        assert!(revoked.load(Ordering::Relaxed));
        let count: i64 = Connection::open(&db_path)?.query_row(
            "SELECT count(*) FROM emergency_cleanup",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        let events: Value = client
            .get(format!("{root}/events?wait=0s"))
            .bearer_auth("owner")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        assert_eq!(events["events"][3]["type"], "session.revoked");
        assert!(!events.to_string().contains("test-issued-token"));
        task.abort();
        kube_task.abort();
        Ok(())
    }
}
