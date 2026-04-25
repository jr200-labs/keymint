package tracing

import (
	"context"
	"testing"
)

func TestSetup_DisabledByDefault(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_TRACES_EXPORTER", "")

	res, err := Setup(context.Background(), "keymint", "test")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if res == nil || res.Shutdown == nil {
		t.Fatalf("nil result or Shutdown")
	}
	// Shutdown must be safe to call even when tracing is disabled.
	if err := res.Shutdown(context.Background()); err != nil {
		t.Errorf("noop Shutdown returned error: %v", err)
	}
}

func TestSetup_ConsoleExporter(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_TRACES_EXPORTER", "console")

	res, err := Setup(context.Background(), "keymint", "test")
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() {
		_ = res.Shutdown(context.Background())
	})

	tracer := Tracer("keymint/test")
	_, span := tracer.Start(context.Background(), "noop")
	span.End()
}
