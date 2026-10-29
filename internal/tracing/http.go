package tracing

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"io"
	"net/http"
	"sync"
)

// HTTPClient copies the client and instruments its transport. It never records
// URLs, headers or payloads, which may contain credential or ceremony material.
func HTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	transport := copy.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if _, ok := transport.(*httpTransport); !ok {
		copy.Transport = &httpTransport{next: transport}
	}
	return &copy
}

type httpTransport struct{ next http.RoundTripper }

func (transport *httpTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx, span := otel.Tracer("keymint/http").Start(request.Context(), "HTTP "+request.Method, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attribute.String("http.request.method", request.Method), attribute.String("server.address", request.URL.Hostname())))
	copy := request.Clone(ctx)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(copy.Header))
	response, err := transport.next.RoundTrip(copy)
	if err != nil {
		span.SetStatus(codes.Error, "transport failure")
		span.End()
		return response, err
	}
	span.SetAttributes(attribute.Int("http.response.status_code", response.StatusCode))
	if response.StatusCode >= 400 {
		span.SetStatus(codes.Error, "upstream rejected request")
	}
	response.Body = &tracedBody{ReadCloser: response.Body, span: span}
	return response, nil
}

type tracedBody struct {
	io.ReadCloser
	span trace.Span
	once sync.Once
}

func (body *tracedBody) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(func() { body.span.End() })
	return err
}
