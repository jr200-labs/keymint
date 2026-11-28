use anyhow::Result;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry::{
    KeyValue,
    propagation::{Extractor, Injector, TextMapPropagator},
    trace::TracerProvider,
};
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use std::{env, time::Duration};
use tracing::{Instrument, Span, level_filters::LevelFilter};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

pub struct Telemetry(Option<SdkTracerProvider>);

impl Telemetry {
    pub fn init(filter: LevelFilter, human: bool) -> Result<Self> {
        let mut resource = Resource::builder()
            .with_service_name("keymint")
            .with_attribute(KeyValue::new("service.version", env!("KEYMINT_VERSION")));
        if let Ok(environment) = env::var("OTEL_DEPLOYMENT_ENVIRONMENT")
            && !environment.is_empty()
        {
            resource =
                resource.with_attribute(KeyValue::new("deployment.environment", environment));
        }
        let provider = SdkTracerProvider::builder().with_resource(resource.build());
        let stdout = env::var("OTEL_TRACES_EXPORTER").is_ok_and(|value| value == "console");
        let otlp = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok_and(|value| !value.is_empty());
        let provider = if stdout {
            Some(
                provider
                    .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
                    .build(),
            )
        } else if otlp {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .build()?;
            Some(provider.with_batch_exporter(exporter).build())
        } else {
            None
        };
        let tracing_layer = provider
            .as_ref()
            .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("keymint")));
        let logging = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
        let logging = if human {
            logging.boxed()
        } else {
            logging.json().boxed()
        };
        tracing_subscriber::registry()
            .with(logging)
            .with(tracing_layer)
            .with(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(Self(provider))
    }

    pub async fn shutdown(self, timeout: Duration) {
        if let Some(provider) = self.0
            && tokio::task::spawn_blocking(move || provider.shutdown_with_timeout(timeout))
                .await
                .map_or(true, |result| result.is_err())
        {
            tracing::error!("tracing shutdown failed");
        }
    }
}

struct HeaderReader<'a>(&'a HeaderMap);

impl Extractor for HeaderReader<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

struct HeaderWriter(HeaderMap);
impl Injector for HeaderWriter {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(key), Ok(value)) = (key.parse::<HeaderName>(), value.parse::<HeaderValue>()) {
            self.0.insert(key, value);
        }
    }
}

pub fn incoming(span: &Span, headers: &HeaderMap) {
    let parent = TraceContextPropagator::new().extract(&HeaderReader(headers));
    let _ = span.set_parent(parent);
}

pub async fn send(
    request: reqwest::RequestBuilder,
    method: &'static str,
) -> reqwest::Result<reqwest::Response> {
    let span = tracing::info_span!(
        "upstream request",
        otel.kind = "client",
        http.request.method = method,
        http.response.status_code = tracing::field::Empty
    );
    async {
        let mut headers = HeaderWriter(HeaderMap::new());
        TraceContextPropagator::new().inject_context(&Span::current().context(), &mut headers);
        let result = request.headers(headers.0).send().await;
        if let Ok(response) = &result {
            Span::current().record("http.response.status_code", response.status().as_u16());
        }
        result
    }
    .instrument(span)
    .await
}
