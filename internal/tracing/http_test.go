package tracing

import (
	"context"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientPropagatesAndRedacts(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	old := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	defer otel.SetTracerProvider(old)
	oldPropagation := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(oldPropagation)
	parentID, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	parentSpan, _ := trace.SpanIDFromHex("2222222222222222")
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: parentID, SpanID: parentSpan, TraceFlags: trace.FlagsSampled}))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extracted := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		if trace.SpanContextFromContext(extracted).TraceID() != parentID {
			t.Error("upstream lost parent trace")
		}
		w.WriteHeader(503)
	}))
	defer upstream.Close()
	req, _ := http.NewRequestWithContext(ctx, "GET", upstream.URL+"/secret-path?secret=query", nil)
	req.Header.Set("Authorization", "Bearer secret")
	response, err := HTTPClient(upstream.Client()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	spans := recorder.Ended()
	if len(spans) != 1 || spans[0].Parent().SpanID() != parentSpan {
		t.Fatal("client span lacks parent")
	}
	for _, attr := range spans[0].Attributes() {
		if attr.Key == "url.full" || attr.Key == "http.url" {
			t.Fatal("sensitive URL recorded")
		}
	}
}
