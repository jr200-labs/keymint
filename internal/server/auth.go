package server

import (
	"context"
	"github.com/jr200-labs/keymint/internal/logging"
	"github.com/jr200-labs/keymint/internal/metrics"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	"net"
	"net/http"
	"time"
)

type authenticator struct {
	reviewer                   TokenReviewer
	reviewCache                *reviewCache
	preAuthLimit, subjectLimit *limiterMap
	metrics                    *metrics.Metrics
	flights                    singleflight.Group
}
type authFailure struct {
	status           int
	outcome, message string
}

func (f *authFailure) Error() string { return f.message }
func newAuthenticator(reviewer TokenReviewer, m *metrics.Metrics) *authenticator {
	return &authenticator{reviewer: reviewer, metrics: m, reviewCache: newReviewCache(), preAuthLimit: newLimiterMap(rate.Limit(10), 20), subjectLimit: newLimiterMap(rate.Limit(100), 200)}
}
func (a *authenticator) authenticate(ctx context.Context, r *http.Request, proxies []*net.IPNet) (subject string, failure *authFailure) {
	ctx, span := tracer.Start(ctx, "authenticate")
	defer span.End()
	started := time.Now()
	defer func() {
		var err error
		outcome := "accepted"
		if failure != nil {
			err = failure
			outcome = failure.outcome
			span.SetStatus(codes.Error, failure.message)
		}
		span.SetAttributes(attribute.String("keymint.auth.outcome", outcome))
		a.metrics.ObserveOperation("authenticate", started, err)
	}()
	if !a.preAuthLimit.allow(clientIP(r, proxies)) {
		return "", &authFailure{http.StatusTooManyRequests, metrics.OutcomeRateLimited, "too many requests"}
	}
	bearer, ok := bearerToken(r)
	if !ok {
		return "", &authFailure{http.StatusUnauthorized, metrics.OutcomeBadAuth, "missing or malformed Authorization header"}
	}
	subject, hit := a.reviewCache.get(bearer)
	cacheResult := metrics.CacheMiss
	if hit {
		cacheResult = metrics.CacheHit
	}
	if a.metrics != nil {
		a.metrics.TokenReviewCacheTotal.WithLabelValues(cacheResult).Inc()
	}
	if !hit {
		value, err, _ := a.flights.Do(a.reviewCache.hashToken(bearer), func() (any, error) {
			if cached, ok := a.reviewCache.get(bearer); ok {
				return cached, nil
			}
			reviewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			name, accepted, err := a.reviewer.Review(reviewCtx, bearer)
			result := metrics.TokenReviewAccepted
			if err != nil {
				result = "error"
			} else if !accepted {
				result = metrics.TokenReviewRejected
			}
			if a.metrics != nil {
				a.metrics.TokenReviewsTotal.WithLabelValues(result).Inc()
			}
			if err != nil {
				return "", err
			}
			if !accepted {
				a.reviewCache.putNegative(bearer)
				return reviewNegSentinel, nil
			}
			a.reviewCache.putPositive(bearer, name)
			return name, nil
		})
		if err != nil {
			logging.FromContext(ctx).Error("TokenReview unavailable", zap.Error(err))
			return "", &authFailure{http.StatusServiceUnavailable, metrics.OutcomeTokenReviewError, "kubernetes tokenreview unavailable; retry"}
		}
		subject = value.(string)
	}
	if subject == reviewNegSentinel {
		return "", &authFailure{http.StatusUnauthorized, metrics.OutcomeTokenReviewError, "tokenreview rejected the bearer token"}
	}
	if !a.subjectLimit.allow(subject) {
		return "", &authFailure{http.StatusTooManyRequests, metrics.OutcomeRateLimited, "too many requests"}
	}
	span.SetAttributes(attribute.String("k8s.serviceaccount.subject", subject))
	return subject, nil
}
