use anyhow::Result;
use axum::{
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use std::{sync::Arc, time::Instant};
use tracing::Instrument;

pub struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    in_flight: IntGauge,
    mint_requests: IntCounterVec,
    mint_duration: HistogramVec,
    mint_in_flight: IntGauge,
    tokenreviews: IntCounterVec,
    review_cache: IntCounterVec,
    operations: IntCounterVec,
    operation_duration: HistogramVec,
    github_latency: HistogramVec,
    clock_offset: GaugeVec,
    rate_limit: GaugeVec,
    rate_reset: GaugeVec,
    endpoint_breakers: GaugeVec,
    breaker: IntGauge,
    cleanup_records: IntGauge,
    cleanup_due: IntGauge,
    cleanup_oldest: IntGauge,
    telegram_requests: IntCounterVec,
    telegram_duration: HistogramVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new_custom(Some("keymint".into()), None)?;
        let requests = IntCounterVec::new(
            Opts::new(
                "http_requests_total",
                "HTTP requests by route, method and status.",
            ),
            &["route", "method", "status"],
        )?;
        let duration = HistogramVec::new(
            HistogramOpts::new("http_duration_seconds", "HTTP handler duration by route."),
            &["route"],
        )?;
        let in_flight = IntGauge::new("http_in_flight", "In-flight HTTP handlers.")?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(duration.clone()))?;
        registry.register(Box::new(in_flight.clone()))?;
        let counter = |name, help, labels: &[&str]| -> Result<IntCounterVec> {
            let value = IntCounterVec::new(Opts::new(name, help), labels)?;
            registry.register(Box::new(value.clone()))?;
            Ok(value)
        };
        let histogram = |name, help, labels: &[&str]| -> Result<HistogramVec> {
            let value = HistogramVec::new(HistogramOpts::new(name, help), labels)?;
            registry.register(Box::new(value.clone()))?;
            Ok(value)
        };
        let gauge_vec = |name, help, labels: &[&str]| -> Result<GaugeVec> {
            let value = GaugeVec::new(Opts::new(name, help), labels)?;
            registry.register(Box::new(value.clone()))?;
            Ok(value)
        };
        let gauge = |name, help| -> Result<IntGauge> {
            let value = IntGauge::new(name, help)?;
            registry.register(Box::new(value.clone()))?;
            Ok(value)
        };
        Ok(Self {
            mint_requests: counter(
                "mint_requests_total",
                "Installation token requests by outcome and key.",
                &["outcome", "key"],
            )?,
            mint_duration: histogram(
                "mint_duration_seconds",
                "Installation token handler duration.",
                &["key"],
            )?,
            mint_in_flight: gauge("mint_in_flight", "In-flight installation token requests.")?,
            tokenreviews: counter(
                "tokenreviews_total",
                "Kubernetes TokenReview results.",
                &["result"],
            )?,
            review_cache: counter(
                "tokenreview_cache_total",
                "TokenReview cache lookups.",
                &["result"],
            )?,
            operations: counter(
                "operations_total",
                "Internal operations by operation and outcome.",
                &["operation", "outcome"],
            )?,
            operation_duration: histogram(
                "operation_duration_seconds",
                "Internal operation latency.",
                &["operation"],
            )?,
            github_latency: histogram(
                "github_api_latency_seconds",
                "Installation token exchange latency.",
                &["status", "api_base_url"],
            )?,
            clock_offset: gauge_vec(
                "jwt_clock_offset_seconds",
                "GitHub API clock offset.",
                &["api_base_url"],
            )?,
            rate_limit: gauge_vec(
                "github_ratelimit_remaining",
                "GitHub request quota remaining.",
                &["api_base_url"],
            )?,
            rate_reset: gauge_vec(
                "github_ratelimit_reset_unix",
                "GitHub request quota reset time.",
                &["api_base_url"],
            )?,
            endpoint_breakers: gauge_vec(
                "github_endpoint_breaker_state",
                "GitHub circuit breaker state.",
                &["api_base_url"],
            )?,
            breaker: gauge(
                "github_breaker_state",
                "Worst GitHub circuit breaker state.",
            )?,
            cleanup_records: gauge(
                "credential_cleanup_records",
                "Tracked emergency cleanup records.",
            )?,
            cleanup_due: gauge(
                "credential_cleanup_due",
                "Emergency cleanup records ready to revoke.",
            )?,
            cleanup_oldest: gauge(
                "credential_cleanup_oldest_overdue_seconds",
                "Age of oldest overdue cleanup record.",
            )?,
            telegram_requests: counter(
                "telegram_requests_total",
                "Telegram requests by action and outcome.",
                &["action", "outcome"],
            )?,
            telegram_duration: histogram(
                "telegram_request_duration_seconds",
                "Telegram request duration.",
                &["action"],
            )?,
            registry,
            requests,
            duration,
            in_flight,
        })
    }

    pub fn mint_started(&self) -> GaugeGuard<'_> {
        self.mint_in_flight.inc();
        GaugeGuard(&self.mint_in_flight)
    }

    pub fn mint_outcome(&self, key: &str, code: StatusCode, start: Instant) {
        let outcome = match code {
            StatusCode::OK => "success",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::UNAUTHORIZED => "bad_auth",
            StatusCode::NOT_FOUND => "unknown_key",
            StatusCode::SERVICE_UNAVAILABLE => "tokenreview_error",
            StatusCode::TOO_MANY_REQUESTS => "rate_limited",
            StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE => "invalid_scope",
            _ => "mint_error",
        };
        self.mint_requests.with_label_values(&[outcome, key]).inc();
        self.mint_duration
            .with_label_values(&[key])
            .observe(start.elapsed().as_secs_f64());
    }

    pub fn review(&self, result: &str) {
        self.tokenreviews.with_label_values(&[result]).inc();
    }
    pub fn review_cache(&self, hit: bool) {
        self.review_cache
            .with_label_values(&[if hit { "hit" } else { "miss" }])
            .inc();
    }
    pub fn operation(&self, name: &str, success: bool, start: Instant) {
        self.operations
            .with_label_values(&[name, if success { "success" } else { "error" }])
            .inc();
        self.operation_duration
            .with_label_values(&[name])
            .observe(start.elapsed().as_secs_f64());
    }

    pub fn exchange(&self, base: &str, status: &str, headers: Option<&HeaderMap>, start: Instant) {
        self.github_latency
            .with_label_values(&[status, base])
            .observe(start.elapsed().as_secs_f64());
        let Some(headers) = headers else {
            return;
        };
        let number = |key| {
            headers
                .get(key)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<i64>().ok())
        };
        if let Some(remaining) = number("X-RateLimit-Remaining").filter(|remaining| *remaining >= 0)
        {
            self.rate_limit
                .with_label_values(&[base])
                .set(remaining as f64);
            if let Some(reset) = number("X-RateLimit-Reset").filter(|reset| *reset > 0) {
                self.rate_reset.with_label_values(&[base]).set(reset as f64);
            }
        }
    }

    pub fn clock(&self, base: &str, seconds: i64) {
        self.clock_offset
            .with_label_values(&[base])
            .set(seconds as f64);
    }

    pub fn breaker(&self, base: &str, state: i64, worst: i64) {
        self.endpoint_breakers
            .with_label_values(&[base])
            .set(state as f64);
        self.breaker.set(worst);
    }

    pub fn cleanup(&self, total: i64, due: i64, oldest: i64) {
        self.cleanup_records.set(total);
        self.cleanup_due.set(due);
        self.cleanup_oldest.set(oldest.max(0));
    }

    pub async fn handle(State(metrics): State<Arc<Self>>) -> Response {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        match encoder.encode(&metrics.registry.gather(), &mut buffer) {
            Ok(()) => ([(header::CONTENT_TYPE, encoder.format_type())], buffer).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    pub async fn observe(
        State(metrics): State<Arc<Self>>,
        request: Request,
        next: Next,
    ) -> Response {
        struct InFlight<'a>(&'a IntGauge);
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                self.0.dec();
            }
        }
        metrics.in_flight.inc();
        let _in_flight = InFlight(&metrics.in_flight);
        let start = Instant::now();
        let route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|matched| matched.as_str().to_owned())
            .unwrap_or_else(|| "unknown".into());
        let method = match *request.method() {
            axum::http::Method::GET => "GET",
            axum::http::Method::POST => "POST",
            axum::http::Method::DELETE => "DELETE",
            axum::http::Method::HEAD => "HEAD",
            _ => "OTHER",
        };
        let action = match route.as_str() {
            "/telegram-enrollments/{relay}" => Some("approval"),
            "/telegram-relays/{relay}/wrapping-key" => Some("wrapping_key"),
            "/telegram-enrollments/{relay}/{id}/{action}" => {
                let action = request.uri().path().rsplit('/').next().unwrap_or_default();
                Some(match action {
                    "start" => "start",
                    "status" => "status",
                    "qr" => "qr",
                    "commit" => "commit",
                    "cancel" => "cancel",
                    "password" => "password",
                    _ => "unknown",
                })
            }
            _ => None,
        };
        let span = tracing::info_span!("HTTP request", otel.kind = "server", http.route = %route,
            http.request.method = method, http.response.status_code = tracing::field::Empty);
        crate::telemetry::incoming(&span, request.headers());
        let response = next.run(request).instrument(span.clone()).await;
        span.record("http.response.status_code", response.status().as_u16());
        let status = response.status().as_u16().to_string();
        metrics
            .requests
            .with_label_values(&[&route, method, &status])
            .inc();
        metrics
            .duration
            .with_label_values(&[&route])
            .observe(start.elapsed().as_secs_f64());
        if let Some(action) = action {
            let outcome = match response.status() {
                StatusCode::OK => "success",
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "access_denied",
                StatusCode::CONFLICT => "relay_conflict",
                StatusCode::BAD_GATEWAY => "relay_http_error",
                StatusCode::NOT_FOUND => "unknown_action",
                StatusCode::BAD_REQUEST => "invalid_password_request",
                _ => "internal_error",
            };
            metrics
                .telegram_requests
                .with_label_values(&[action, outcome])
                .inc();
            metrics
                .telegram_duration
                .with_label_values(&[action])
                .observe(start.elapsed().as_secs_f64());
        }
        tracing::info!(parent: &span, %route, method, %status, "HTTP request");
        response
    }
}

pub struct GaugeGuard<'a>(&'a IntGauge);
impl Drop for GaugeGuard<'_> {
    fn drop(&mut self) {
        self.0.dec();
    }
}
