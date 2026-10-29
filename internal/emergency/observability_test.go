package emergency

import (
	"context"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"testing"
	"time"
)

func TestCleanupAndJournalFailureObservations(t *testing.T) {
	old := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = old }()
	m := metrics.New()
	status, calls := 503, 0
	service, err := New(&config.Config{}, cleanupClient(&status, &calls), nil, m)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	profile := config.EmergencyProfile{ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{1}}
	if err = service.rememberCredential(context.Background(), "session", profile, "token", "", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = service.drainCleanup(context.Background(), false); err == nil {
		t.Fatal("upstream failure ignored")
	}
	value := &dto.Metric{}
	_ = m.CleanupDue.Write(value)
	if value.GetGauge().GetValue() != 1 {
		t.Fatal("missing cleanup backlog")
	}
	_ = m.OperationsTotal.WithLabelValues("credential_revoke", "error").Write(value)
	if value.GetCounter().GetValue() != 1 {
		t.Fatal("missing revocation failure")
	}
	if err = service.events.append(context.Background(), Event{}); err == nil {
		t.Fatal("invalid event accepted")
	}
	_ = m.OperationsTotal.WithLabelValues("journal_append", "error").Write(value)
	if value.GetCounter().GetValue() != 1 {
		t.Fatal("missing journal failure")
	}
}
