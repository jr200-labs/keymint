# keymint

Broker short-lived GitHub credentials and destination-bound release-signing
ciphertext for CLI and in-cluster callers.

## What it does

- **CLI mode**: reads a SOPS-encrypted GitHub App private key, signs a
  JWT, exchanges it for an installation access token, and prints the
  token to stdout. Pair with `git config credential.helper` to auth
  `git push` / `gh` invocations on private repos.
- **Service mode**: runs as an HTTP server inside Kubernetes. Validates
  inbound bearer tokens against the cluster's TokenReview API; if the
  caller's ServiceAccount is in the configured allowlist, mints an
  installation token and returns it.
- **Emergency sessions**: re-authenticate a human with a WebAuthn passkey,
  GitHub OAuth App device flow, or TOTP, then issue a session-scoped GitHub user or Secret-bound
  Kubernetes token to the authenticated workload. The credential stays in
  trusted process memory; expiry remotely revokes the OAuth token or deletes
  the Kubernetes binding Secret. Kubernetes profiles may use either method;
  Direct passkeys work with the browser's configured provider; TOTP remains the
  external-service-independent enrollment and recovery method.
- **Release-key sealing**: after an active emergency session, read an
  allowlisted Sparkle Ed25519 private-key export from a Secret-mounted file and seal it
  directly to GitHub's repository Actions public key. The API returns the
  derived public signing key and ciphertext, never the plaintext private key. A
  key may serve multiple internal projects, but every repository must be listed
  explicitly in its release-key configuration.

The two modes share the same Go binary, the same config schema, and
the same JWT/HTTP signing logic — so you can adopt CLI-only for solo
dev and bolt on the service later (or vice versa) without rewriting
anything.

## Status

Early scaffold. Implementation lands in a sequence of small PRs:

| PR | Scope |
|----|-------|
| 1  | Repo scaffold (you are here) |
| 2  | `internal/mint` — JWT signing + `/access_tokens` |
| 3  | `internal/sops` + `internal/config` — config + SOPS decrypt |
| 4  | `internal/credhelper` — git credential helper protocol |
| 5  | `internal/server` — HTTP serve mode + TokenReview |
| 6  | Container image release wiring |
| 7  | Homebrew formula |

## Contributing

This repo follows the jr200-labs convention:

- **`master` is protected** — direct pushes are blocked. Land changes via PR.
- **Squash-and-merge only** — merge commits and rebase merges are
  disabled. Each PR collapses to one commit on `master`. Branches are
  deleted automatically after merge.
- **Conventional Commits** — the squashed commit title becomes the PR
  title, so PR titles must follow the
  [Conventional Commits](https://www.conventionalcommits.org) spec
  (`feat: ...`, `fix(scope): ...`, etc.). CI runs `commitlint` on
  individual commits in the branch as well.
- **release-please** drives versioning. Never bump versions by hand;
  push conventional commits and let the Release PR open itself.

## Development setup

Install pre-commit hooks once after cloning. Hooks run `gofmt`, `go vet`,
`golangci-lint` (with the same shared config CI uses) on staged Go files
and `commitlint` on commit messages:

```sh
make hooks-install
```

Run hooks against every file in the repo:

```sh
make hooks-run
```

`pre-commit` itself comes from
[pre-commit.com](https://pre-commit.com); install via `brew install pre-commit`
or `uv tool install pre-commit`.

## Build

```sh
make build
```

Produces `build/keymint-$(GOOS)-$(GOARCH)` — static, CGO-disabled.

## Test

```sh
make test       # unit tests
make test-race  # with race detector + coverage
```

## Service-mode security requirements

Service mode enforces several invariants. Operators must configure
the deploy accordingly:

- **Audience-bound TokenReview.** The keymint config must set
  `expected_audiences:` to a non-empty list. keymint forwards those
  audiences into the `TokenReview` API and rejects any inbound token
  whose audiences don't intersect with them. Configure callers'
  projected ServiceAccount volumes with a matching `audience:` value
  (e.g. `keymint`).

  ```yaml
  expected_audiences: [keymint]
  ```

- **SA token rotation.** keymint re-reads its own pod's projected SA
  token from `/var/run/secrets/kubernetes.io/serviceaccount/token` on
  every `TokenReview` call. Use a projected SA volume so the kubelet
  rotates the token in place; do not bake the token into an env var.

- **Actionable permission errors.** When GitHub explicitly rejects token
  permissions that the installation has not granted, `POST /token/<key>`
  returns HTTP 422 with `code: github_permissions_not_granted` and a readable
  `error` naming the key and requested permissions. Update the GitHub App
  permissions and approve the installation update, or reduce the requested
  scope. The requested list does not identify which permission is missing.
  Unclassified mint failures remain HTTP 500 with `error: mint failed`;
  internal errors and arbitrary upstream response bodies are not disclosed.

- **Two-tier rate limiting.** Inbound requests are rate-limited
  per-remote-IP before authentication (10 r/s, burst 20) and
  per-resolved-ServiceAccount after authentication (100 r/s, burst
  200). A flooder cannot exhaust an authenticated caller's bucket.

- **Single-flight token caching.** When a cached installation token
  expires, only one in-flight request actually mints a new one;
  others wait and reuse its result. Prevents thundering-herd
  scenarios from triggering GitHub's secondary rate limits.

- **Per-endpoint clock-drift tracking.** GitHub `Date`-header drift
  is cached separately for `api.github.com` and any GitHub
  Enterprise base URL configured per key. A sick GHE clock cannot
  poison signing for unrelated endpoints.

- **Bounded rate limiters.** Both pre-auth (per-IP) and post-auth
  (per-subject) rate limiters live behind LRUs sized to a few
  thousand entries. A flood of unique IPs or subjects evicts older
  buckets instead of growing memory without bound.

- **Hot key rotation.** Operators rotating the kubernetes Secret
  carrying an App PEM are picked up automatically — keymint
  compares mtime+size of the on-disk file before reusing a parsed
  RSA key, and reloads when either changes.

- **TokenReview circuit breaker.** Calls to the kubernetes API are
  guarded by a circuit breaker that opens for 30s when failure
  ratio crosses 50% over a 60s window, so apiserver degradation
  fails fast instead of stalling the request handler pool.

- **Bounded GitHub egress concurrency.** A semaphore caps in-flight
  POSTs to GitHub at 50 across all keys; bursts queue rather than
  fan out without limit and trigger secondary rate limits.

- **Background token refresh.** Tokens are returned from cache while
  ≥5 min remain; between 5 min and 1 min remaining keymint hands
  back the still-valid cached token and refreshes asynchronously
  via singleflight; below 1 min it refreshes synchronously. No
  guaranteed latency spike at the 5-min mark.

- **Tuned outbound HTTP transports.** Both the kubernetes-API client
  and the GitHub-API client set explicit `MaxIdleConnsPerHost`,
  `IdleConnTimeout`, `TLSHandshakeTimeout`, and
  `ResponseHeaderTimeout` instead of inheriting stdlib defaults.

- **TokenReview cache (positive + negative).** Successful TokenReview results are cached for ~60 s and rejections for ~15 s, both in LRUs keyed by the SHA-256 of the bearer token. Bursty legitimate callers don't amplify into the kubernetes API; bursts of invalid/revoked tokens (misconfigured CI, attackers) also collapse to one apiserver call per TTL window. Revoked ServiceAccounts lose access on the next positive-TTL boundary.

- **Split liveness / readiness probes.** `/livez` returns 200 immediately with no I/O — the right thing for a liveness probe (a transient FS hiccup won't kill the pod). `/readyz` performs the deeper config + projected-volume `os.Stat` checks — the right thing for a readiness probe. `/healthz` is kept as a back-compat alias for `/readyz`.

- **Debounced config reloads.** The fsnotify-driven reload coalesces a 500ms quiet-period of events before invoking `srv.Reload`, so the kubelet's flurry of symlink-swap / permission events on a ConfigMap or Secret update collapses to a single reload against the fully-settled new state.

- **Hot config reload.** keymint watches `--config` via fsnotify.
  When the file changes (operator updates Keys / Allowlist) the new
  config is validated and the in-process snapshot is swapped
  atomically. Pod restarts are not required for routine admin
  changes. (Note: `expected_audiences` is read at startup only —
  changes there require a restart, as do passkey and emergency journal settings; reload rejects such changes.)

- **GitHub API circuit breaker.** Calls to
  `/app/installations/<id>/access_tokens` are wrapped in a circuit
  breaker that opens for 30 s after sustained 5xx or transport
  failures. 4xx responses (bad JWT, suspended app) are
  caller-config bugs and don't count against it.

- **Per-endpoint isolation.** The GitHub circuit breaker, egress concurrency semaphore, and rate-limit metrics are partitioned by API base URL. A degraded GHE host cannot trip a breaker shared with public github.com, exhaust the egress slots for an unrelated endpoint, or be charged against another host's rate-limit gauge. `429 Too Many Requests` is treated as an infra failure (not a 4xx caller error) so the breaker actually opens against secondary rate-limits and avoids escalating bans.

- **Lock-free per-key rate limiter.** Both pre-auth (per-IP) and post-auth (per-subject) limiters use `sync.Map.LoadOrStore`; there is no global mutex on the miss path. A flood of unique spoofed source IPs cannot serialise the HTTP ingest pipeline behind one lock.

- **Case-insensitive Bearer scheme.** Per RFC 7235 §2.1, `Authorization: bearer ...` and `BEARER ...` are accepted alongside `Bearer ...`, so callers behind proxies that normalise the scheme are not spuriously rejected.

- **Bounded token / key caches.** Both the parsed-key and minted-token caches are `expirable.LRU` instances (256 / 1024 entries; 24h / 70min TTL respectively). PEM rotations and config reloads no longer accumulate stale generation entries indefinitely.

- **Cryptographic audit fingerprint.** Each minted installation token is hashed with SHA-256 and the hex digest is emitted as a `token_fingerprint` field on the structured log line and as a `keymint.token_fingerprint` OpenTelemetry span attribute. If a token ever leaks (in CI logs, a screenshot, etc.), security teams can hash it locally and grep audit logs to pinpoint the exact pod, ServiceAccount, and minute that issued it — without ever persisting the raw token.

- **RSA App private keys.** GitHub App JWTs require RS256. PKCS#1 and PKCS#8 RSA keys are accepted; other App key types are rejected. Sparkle release signing continues to use Ed25519.

- **Trusted-proxy-aware client IP extraction.** Set
  `trusted_proxies:` in the config to a list of CIDR blocks for your
  Ingress controller / API gateway / mesh sidecar. When the
  immediate peer is in one of those blocks, keymint walks the
  `X-Forwarded-For` chain right-to-left (then falls back to
  `X-Real-IP`) to recover the real client IP for the per-IP rate
  limiter. Empty (the default) keeps using the raw peer address —
  spoofing-safe but useless behind a proxy.

  ```yaml
  trusted_proxies:
    - 10.0.0.0/8        # cluster pod CIDR
    - 192.168.1.5/32    # specific load balancer
  ```

- **Stale-but-valid token fallback.** If a synchronous refresh
  fails (GitHub timeout, 5xx) but the previously-cached token
  still has any validity left, keymint logs the failure and hands
  back the cached token instead of failing the request. Callers
  get a usable token; the next call retries the refresh.

- **GitHub rate-limit observability.** Each `/access_tokens`
  response's `X-RateLimit-Remaining` and `X-RateLimit-Reset`
  headers are exported as Prometheus gauges
  (`keymint_github_ratelimit_remaining{api_base_url}`,
  `keymint_github_ratelimit_reset_unix{api_base_url}`). Breaker
  state is exposed as `keymint_github_breaker_state` (0 closed,
  1 half-open, 2 open).

## Observability

Service mode emits structured (zap) logs, OpenTelemetry traces, and
Prometheus metrics.

- **Logs** — unsampled JSON by default, with trace/span IDs on request logs. Control via `--log-level` and
  `--log-human` flags.
- **Tracing** — opt in by setting `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP
  gRPC) or `OTEL_TRACES_EXPORTER=console` (stdout, dev). Disabled if
  neither is set. `OTEL_DEPLOYMENT_ENVIRONMENT` adds a deployment
  environment resource attribute. All HTTP routes extract incoming trace context;
  authentication and GitHub/Kubernetes/OAuth calls create child spans and
  propagate context. Dependency attributes omit URLs, headers and bodies.
- **Metrics** — scrapeable on a separate listener (default `:9100`,
  configurable via `--metrics-listen`). Exported series:
  - `keymint_mint_requests_total{outcome,key}`
  - `keymint_mint_duration_seconds{key}` (histogram)
  - `keymint_mint_in_flight`
  - `keymint_tokenreviews_total{result}`
  - `keymint_github_api_latency_seconds{status,api_base_url}` (histogram)
  - `keymint_jwt_clock_offset_seconds{api_base_url}`

Additional route metrics are `keymint_http_requests_total{route,method,status}`,
`keymint_http_duration_seconds{route}` and `keymint_http_in_flight`. Routes use
registered patterns, with a fixed unmatched label. Internal operations expose
`keymint_operations_total{operation,outcome}` and
`keymint_operation_duration_seconds{operation}` for authentication, cache/refresh,
revocation, journal writes and reloads. Cleanup gauges are
`keymint_credential_cleanup_records`, `keymint_credential_cleanup_due`, and
`keymint_credential_cleanup_oldest_overdue_seconds`. Alert on sustained due work,
increasing overdue age, journal errors and failed reloads. Per-endpoint breaker
state is `keymint_github_endpoint_breaker_state{api_base_url}`.

Dashboards using the exchange latency or clock offset metrics must account for
the new `api_base_url` label. These signals cover the service's application paths;
cluster scrape, exporter delivery and alert routing still require deployment checks.

The metrics listener should be reachable only from your monitoring
namespace; use a NetworkPolicy to lock it down.

## Using as a git credential helper

Once `keymint mint <key>` works, you can wire it as a credential
helper so `git push` and `gh` calls against your configured orgs
authenticate automatically:

```sh
git config --global credential.https://github.com.helper "keymint helper"
git config --global credential.https://github.com.useHttpPath true
```

`useHttpPath = true` is required: by default git only sends `host` to
credential helpers, so every `github.com` remote looks identical and
keymint cannot tell which org's App should sign the token.

## Releasing

Releases are fully automated via release-please. Each PR merged to
`master` (squash, conventional commit) is picked up by release-please,
which keeps an open Release PR with the next version + changelog.
Merging that Release PR tags the version and cuts a GitHub Release,
which dispatches the container build to ghcr.io.

Never bump versions by hand.

## License

MIT — see [LICENSE](LICENSE).

### Restricted OAuth emergency sessions

`POST /emergency/sessions` accepts an optional `scopes` array. Nonempty scopes
must be an exact subset of the allowed `github_user` profile's configured OAuth
scopes; other providers and additional permissions are rejected before device
authorization starts. For example, an administrative profile containing `repo`,
`workflow`, and `admin:org` can issue a session requesting only `repo` and
`workflow`, using the same OAuth application and workload allowlist. Omit the
field to retain the configured profile's normal permissions.

The session exposes its restriction as `scopes`. Restricted sessions validate
the scopes returned by GitHub at token exchange; missing, extra or insufficient
grants are rejected and token revocation is attempted. This prevents prior OAuth
authorizations from silently broadening a reduced request. OAuth `repo` remains
a broad permission, not a per-repository restriction. Consumers must enforce
their own operation and repository approvals and must not reuse a broader session.

### Release-key destination lookup

Each `release_keys` entry must set `github_key` to a configured installation
key. That installation must be able to read Actions secrets metadata for every
listed repository. The broker mints a repository-scoped token with `secrets:
read` and obtains the encryption key directly from the configured HTTPS GitHub
API. Caller-supplied destination fields are optional and, when present, must
match the broker lookup. Existing deployments must add `github_key` before
upgrading; unbound release-key configuration fails validation.

### Emergency cleanup storage

Service deployments with emergency profiles must configure
`emergency_state_file` on persistent storage. Keep its adjacent `.cleanup-key`
file with the database, restrict both to the broker identity, and run one
replica. Live authorization remains memory-only, but encrypted revocation
records survive restart until remote cleanup succeeds. The event stream never
contains tokens or revocation secrets. Losing either persistent file prevents
reliable cleanup; retain both during upgrades and recovery.
