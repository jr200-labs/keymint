package server

import (
	"github.com/jr200-labs/keymint/internal/logging"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.status = status
	w.written = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(value []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) observeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header)), "http.request", trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		r = r.WithContext(ctx)
		started := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		if s.metrics != nil {
			s.metrics.HTTPInFlight.Inc()
			defer s.metrics.HTTPInFlight.Dec()
		}
		defer func() {
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			method := r.Method
			switch method {
			case "GET", "POST", "DELETE", "PUT", "PATCH", "HEAD", "OPTIONS":
			default:
				method = "other"
			}
			logging.FromContext(ctx).Info("HTTP request completed", zap.String("route", route), zap.String("method", method), zap.Int("status", wrapped.status), zap.Duration("duration", time.Since(started)))
			span.SetName(route)
			span.SetAttributes(attribute.String("http.route", route), attribute.String("http.request.method", method), attribute.Int("http.response.status_code", wrapped.status))
			if wrapped.status >= 500 {
				span.SetStatus(codes.Error, "request failed")
			}
			if s.metrics != nil {
				s.metrics.HTTPRequests.WithLabelValues(route, method, strconv.Itoa(wrapped.status)).Inc()
				s.metrics.HTTPDuration.WithLabelValues(route).Observe(time.Since(started).Seconds())
			}
		}()
		next.ServeHTTP(wrapped, r)
	})
}
