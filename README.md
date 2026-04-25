# keymint

Mint short-lived GitHub App installation tokens — for use as a CLI on
your laptop or as an in-cluster broker service.

## What it does

- **CLI mode**: reads a SOPS-encrypted GitHub App private key, signs a
  JWT, exchanges it for an installation access token, and prints the
  token to stdout. Pair with `git config credential.helper` to auth
  `git push` / `gh` invocations on private repos.
- **Service mode**: runs as an HTTP server inside Kubernetes. Validates
  inbound bearer tokens against the cluster's TokenReview API; if the
  caller's ServiceAccount is in the configured allowlist, mints an
  installation token and returns it.

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
  changes there require a restart.)

- **GitHub API circuit breaker.** Calls to
  `/app/installations/<id>/access_tokens` are wrapped in a circuit
  breaker that opens for 30 s after sustained 5xx or transport
  failures. 4xx responses (bad JWT, suspended app) are
  caller-config bugs and don't count against it.

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

- **Logs** — JSON by default. Control via `--log-level` and
  `--log-human` flags.
- **Tracing** — opt in by setting `OTEL_EXPORTER_OTLP_ENDPOINT` (OTLP
  gRPC) or `OTEL_TRACES_EXPORTER=console` (stdout, dev). Disabled if
  neither is set. `OTEL_DEPLOYMENT_ENVIRONMENT` adds a deployment
  environment resource attribute. Spans wrap the `/token/<key>`
  handler with attributes for the key, k8s subject, and outcome.
- **Metrics** — scrapeable on a separate listener (default `:9100`,
  configurable via `--metrics-listen`). Exported series:
  - `keymint_mint_requests_total{outcome,key}`
  - `keymint_mint_duration_seconds{key}` (histogram)
  - `keymint_mint_in_flight`
  - `keymint_tokenreviews_total{result}`
  - `keymint_github_api_latency_seconds{status}` (histogram)
  - `keymint_jwt_clock_offset_seconds`

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
