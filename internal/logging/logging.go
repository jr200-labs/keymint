package logging

import (
	"context"
	"go.opentelemetry.io/otel/trace"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Setup initializes the global zap logger with the given level and format.
// Level strings: "disabled", "panic", "fatal", "error", "warn", "info", "debug", "trace".
// Trace is mapped to Debug since zap has no trace level.
// If humanReadable is true, uses a development (console) encoder.
func Setup(level string, humanReadable bool) {
	zapLevel := parseLevel(level)

	var cfg zap.Config
	if humanReadable {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
	}
	// Audit events must not disappear through message-based sampling.
	cfg.Sampling = nil
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)

	logger, err := cfg.Build(zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		// Fallback to nop logger if config fails
		logger = zap.NewNop()
	}

	zap.ReplaceGlobals(logger)
}

func parseLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "disabled":
		// Use FatalLevel + 1 to effectively disable all logging
		return zapcore.FatalLevel + 1
	case "panic":
		return zapcore.PanicLevel
	case "fatal":
		return zapcore.FatalLevel
	case "error":
		return zapcore.ErrorLevel
	case "warn":
		return zapcore.WarnLevel
	case "info":
		return zapcore.InfoLevel
	case "debug", "trace":
		return zapcore.DebugLevel
	default:
		return zapcore.InfoLevel
	}
}

// FromContext attaches trace correlation without inspecting request payloads.
func FromContext(ctx context.Context) *zap.Logger {
	logger := zap.L()
	span := trace.SpanContextFromContext(ctx)
	if span.IsValid() {
		logger = logger.With(zap.String("trace_id", span.TraceID().String()), zap.String("span_id", span.SpanID().String()))
	}
	return logger
}
