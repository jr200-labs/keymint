package server

import (
	"context"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"net/http/httptest"
	"testing"
	"time"
)

func testMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	old := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	t.Cleanup(func() { prometheus.DefaultRegisterer = old })
	return metrics.New()
}
func TestEmergencyRequestAndAuthObservations(t *testing.T) {
	m := testMetrics(t)
	cfg := &config.Config{Allowlist: []config.AllowEntry{{Subject: "caller"}}}
	em, _ := activeEmergency(t, cfg)
	srv, err := New(cfg, func(context.Context, config.Key, TokenScope) (string, time.Time, error) { return "", time.Time{}, nil }, &fakeReviewer{subjectByToken: map[string]string{"valid": "caller"}}, m, em)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	for _, token := range []string{"valid", "invalid"} {
		req := httptest.NewRequest("GET", "/emergency/profiles", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		srv.Routes().ServeHTTP(httptest.NewRecorder(), req)
	}
	if got := counterValue(m.HTTPRequests.WithLabelValues("GET /emergency/profiles", "GET", "200")); got != 1 {
		t.Fatalf("success count=%v", got)
	}
	if got := counterValue(m.HTTPRequests.WithLabelValues("GET /emergency/profiles", "GET", "401")); got != 1 {
		t.Fatalf("denial count=%v", got)
	}
	for _, result := range []string{"accepted", "rejected"} {
		if got := counterValue(m.TokenReviewsTotal.WithLabelValues(result)); got != 1 {
			t.Errorf("%s TokenReviews=%v", result, got)
		}
	}
}

func counterValue(counter prometheus.Counter) float64 {
	value := &dto.Metric{}
	_ = counter.Write(value)
	return value.GetCounter().GetValue()
}
