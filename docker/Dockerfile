ARG GOVERSION=1.26
FROM golang:${GOVERSION}-alpine AS builder

ARG BUILD_ARCH
ARG BUILD_OS

RUN apk update && apk add --no-cache git bash curl jq make

WORKDIR /usr/src/app

# Pre-download dependencies for cached layer
COPY go.sum go.mod ./
RUN go mod download

COPY . .

RUN make build && \
    ln -s /usr/src/app/build/keymint-${BUILD_OS}-${BUILD_ARCH} /usr/local/bin/keymint

# Minimal runtime image
FROM alpine:3

LABEL org.opencontainers.image.source="https://github.com/jr200-labs/keymint"
LABEL org.opencontainers.image.description="keymint — GitHub App installation token broker"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates && \
    addgroup -S keymint && adduser -S keymint -G keymint

COPY --from=builder /usr/local/bin/keymint /usr/local/bin/keymint

USER keymint

# Default to service mode; override with `keymint <subcommand>`
ENTRYPOINT ["/usr/local/bin/keymint"]
CMD ["serve"]
