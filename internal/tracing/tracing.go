// Package tracing wires up an OpenTelemetry TracerProvider so the rest
// of keymint can produce spans with go.opentelemetry.io/otel/trace.
//
// Exporter selection (mirrors the convention used by sibling Go
// services in this org so OTel env vars work the same way everywhere):
//
//   - OTEL_EXPORTER_OTLP_ENDPOINT set -> OTLP gRPC exporter
//   - OTEL_TRACES_EXPORTER=console     -> stdout, pretty-printed (dev)
//   - neither set                      -> tracing disabled (no-op)
//
// Sampling is controlled via the OTEL_TRACES_SAMPLER env var; the SDK
// default is `always_on`.
package tracing

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// zapErrorHandler routes OTel SDK internal errors to the zap logger
// rather than silently dropping them.
type zapErrorHandler struct{}

func (zapErrorHandler) Handle(err error) {
	zap.L().Error("OTel SDK error", zap.Error(err))
}

// Result is what Setup returns. Shutdown flushes + closes the
// TracerProvider; callers should defer it before exit.
type Result struct {
	Shutdown func(context.Context) error
}

// Setup initialises the global TracerProvider for the named service.
// If neither OTEL_EXPORTER_OTLP_ENDPOINT nor OTEL_TRACES_EXPORTER=console
// is set, it returns a no-op Result (Shutdown still safe to call).
func Setup(ctx context.Context, serviceName, serviceVersion string) (*Result, error) {
	otel.SetErrorHandler(zapErrorHandler{})

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	tracesExporter := os.Getenv("OTEL_TRACES_EXPORTER")

	if endpoint == "" && tracesExporter != "console" {
		zap.L().Info("OTel tracing disabled (set OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_TRACES_EXPORTER=console to enable)")
		return &Result{Shutdown: func(context.Context) error { return nil }}, nil
	}

	attrs := []resource.Option{
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
			semconv.TelemetrySDKLanguageGo,
		),
	}
	if env := os.Getenv("OTEL_DEPLOYMENT_ENVIRONMENT"); env != "" {
		attrs = append(attrs, resource.WithAttributes(semconv.DeploymentEnvironmentKey.String(env)))
	}

	res, err := resource.New(ctx, attrs...)
	if err != nil {
		return nil, fmt.Errorf("tracing: build resource: %w", err)
	}

	var exporter sdktrace.SpanExporter
	if tracesExporter == "console" {
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	} else {
		exporter, err = otlptracegrpc.New(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("tracing: build exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Result{Shutdown: tp.Shutdown}, nil
}

// Tracer returns a named tracer from the global provider.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}
