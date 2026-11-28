# renovate: datasource=docker depName=rust
ARG RUST_VERSION=1.100.0
FROM rust:${RUST_VERSION}-alpine AS builder

RUN apk add --no-cache build-base
WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .release-please-manifest.json build.rs ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3

LABEL org.opencontainers.image.source="https://github.com/jr200-labs/keymint"
LABEL org.opencontainers.image.description="keymint — GitHub App installation token broker"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates && \
    addgroup -S keymint && adduser -S keymint -G keymint

COPY --from=builder /usr/src/app/target/release/keymint /usr/local/bin/keymint

USER keymint
ENTRYPOINT ["/usr/local/bin/keymint"]
CMD ["serve"]
