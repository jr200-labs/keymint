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
  trusted workload memory; the broker persists encrypted cleanup material before
  delivery. Expiry revokes the OAuth token or deletes the Kubernetes binding
  Secret, with failed cleanup retained for retry. Kubernetes profiles support
  TOTP, GitHub device authentication, or direct passkeys. Passkeys work with the
  browser's configured provider; TOTP remains the external-service-independent
  enrollment and recovery method.
- **Release-key sealing**: after an active emergency session, read an
  allowlisted Sparkle Ed25519 private-key export from a Secret-mounted file and seal it
  directly to GitHub's repository Actions public key. The API returns the
  derived public signing key and ciphertext, never the plaintext private key. A
  key may serve multiple internal projects, but every repository must be listed
  explicitly in its release-key configuration.

- **Telegram owner enrollment**: use passkey approval to authorize QR enrollment
  for a configured account and isolated relay. Keymint renders the QR and
  releases the session wrapping key only to the dedicated relay identity.
  See the [operator interface](docs/adr/0005-control-telegram-owner-enrollment.md).

The two modes share the same Rust binary, the same config schema, and
the same JWT/HTTP signing logic — so you can adopt CLI-only for solo
dev and bolt on the service later (or vice versa) without rewriting
anything.

## Status

CLI minting, the Git credential helper, service authentication, emergency
sessions, passkeys and release-key sealing are implemented. The security review
shipped in [v1.8.1](CHANGELOG.md#181-2026-10-29); verified organization-secret
destinations followed in [v1.9.0](CHANGELOG.md#190-2026-10-30). See the
[remediation record](docs/reviews/2026-10-29-remediation.md) for verification and
remaining integration checks. Releases are published as a container image;
GitHub release and packaging automation live under `.github/workflows`.

The [domain vocabulary](CONTEXT.md) and [architecture decisions](docs/adr/)
describe module boundaries, authentication and durable lifecycle storage.

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

Install pre-commit hooks after cloning to run Rust formatting and lint checks
and validate commit messages.

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

Produces `build/keymint-<os>-<arch>` for the host. Cargo uses the toolchain
pinned in `rust-toolchain.toml` and the dependencies in `Cargo.lock`.

## Test

```sh
make test
make lint
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

- **Installation token requests.** Send an empty body to
  `POST /token/<key>` for a token with the installation's default access,
  or send a JSON object with `repositories` and/or `permissions` to
  narrow its scope. The same rules apply to chunked requests and HTTP/2
  requests without a `Content-Length` header. Bodies larger than 8 KiB
  return HTTP 413. Invalid scopes return HTTP 400.

  To enforce least-privilege minting, set ceilings on a workload's
  `allowlist` entry.

  ```yaml
  allowlist:
    - subject: system:serviceaccount:ci:publisher
      keys: [release-app]
      repositories: [my-project]
      permissions: {contents: write}
      require_scope: true
  ```

  A repository or permission ceiling requires a nonempty explicit request for
  that dimension. `require_scope: true` requires both dimensions. A `write`
  ceiling allows `read` for the same permission. Other permission levels
  require an exact match. Requests outside the allowed scope return HTTP 403
  before Keymint contacts GitHub. Avoid overlapping entries for a restricted
  subject and key. Entries without ceilings retain their previous behavior.
  GitHub can still include mandatory permissions such as metadata access.

- **GitHub API base URL.** Leave `keys.<name>.api_base_url` unset for
  `https://api.github.com`. For GitHub Enterprise Server, specify an
  absolute HTTPS URL such as `https://github.example.com/api/v3`. Keymint
  accepts and trims trailing slashes. Credentials, queries, and fragments
  are invalid in the configured URL.

- **Actionable permission errors.** When GitHub explicitly rejects token
  permissions that the installation has not granted, `POST /token/<key>`
  returns HTTP 422 with `code: github_permissions_not_granted` and a readable
  `error` naming the key and requested permissions. Update the GitHub App
  permissions and approve the installation update, or reduce the requested
  scope. The requested list does not identify which permission is missing.
  Unclassified mint failures remain HTTP 500 with `error: mint failed`;
  internal errors and arbitrary upstream response bodies are not disclosed.

- **Two-tier rate limiting.** Inbound requests are rate-limited
  per-client-IP before authentication (10 r/s, burst 20) and per resolved
  ServiceAccount after authentication (100 r/s, burst 200). When the immediate
  peer matches `trusted_proxies`, Keymint walks all `X-Forwarded-For` header
  values from right to left and uses the first valid IP outside the trusted
  ranges. A malformed hop encountered during the walk falls back to the peer IP.
  When the chain is absent or all its hops are trusted, Keymint uses a valid
  untrusted IP from the last `X-Real-IP` header, then the peer IP. Both limiters keep up to 8,192 buckets and sweep fully refilled buckets every
  30 seconds.

- **Single-flight token caching.** When a cached installation token
  expires, only one in-flight request actually mints a new one;
  others wait and reuse its result. Prevents thundering-herd
  scenarios from triggering GitHub's secondary rate limits.

- **Per-endpoint clock-drift tracking.** GitHub `Date`-header drift
  is cached separately for `api.github.com` and any GitHub
  Enterprise base URL configured per key. A sick GHE clock cannot
  poison signing for unrelated endpoints.

- **Hot key rotation.** Keymint reads the mounted PEM for each mint request
  and uses a content hash to isolate tokens issued for different key versions.

- **TokenReview circuit breaker.** Calls to the kubernetes API are
  guarded by a circuit breaker that opens for 30s when failure
  ratio crosses 50% over a 60s window, so apiserver degradation
  fails fast instead of stalling the request handler pool.

- **Bounded GitHub egress concurrency.** A semaphore caps in-flight
  POSTs to each GitHub API endpoint at 50 across its keys; bursts queue rather than
  fan out without limit and trigger secondary rate limits.

- **Background token refresh.** Tokens are returned from cache while
  ≥5 min remain; between 5 min and 1 min remaining keymint hands
  back the still-valid cached token and refreshes asynchronously
  via singleflight; below 1 min it refreshes synchronously. No
  guaranteed latency spike at the 5-min mark.

- **Tuned outbound HTTP transports.** Kubernetes TokenReview and emergency
  credential issuance share transport settings that bound idle connections,
  TLS handshakes, and response-header waits. Both support IPv6 API server
  addresses. The issuer drains small responses so it can reuse connections.
  The GitHub API client also sets explicit connection and timeout limits.

- **TokenReview cache (positive + negative).** Successful TokenReview results are cached for ~60 s and rejections for ~15 s, both in LRUs keyed by the SHA-256 of the bearer token. Bursty legitimate callers don't amplify into the kubernetes API; bursts of invalid/revoked tokens (misconfigured CI, attackers) also collapse to one apiserver call per TTL window. Revoked ServiceAccounts lose access on the next positive-TTL boundary.

- **Split liveness / readiness probes.** `/livez` returns 200 immediately with no I/O — the right thing for a liveness probe (a transient FS hiccup won't kill the pod). `/readyz` performs the deeper config + projected-volume `os.Stat` checks — the right thing for a readiness probe. `/healthz` is kept as a back-compat alias for `/readyz`.

- **Hot config reload.** Keymint checks the file passed to `--config` for
  changes, validates the candidate, and updates the active policy. Existing
  emergency sessions lose authority if their profile or workload binding
  changes. Audience, passkey, and emergency database changes require a restart.

- **GitHub API circuit breaker.** Calls to
  `/app/installations/<id>/access_tokens` are wrapped in a circuit
  breaker that opens for 30 s after sustained 5xx or transport
  failures. 4xx responses (bad JWT, suspended app) are
  caller-config bugs and don't count against it.

- **Per-endpoint isolation.** The GitHub circuit breaker, egress concurrency semaphore, and rate-limit metrics are partitioned by API base URL. A degraded GHE host cannot trip a breaker shared with public github.com, exhaust the egress slots for an unrelated endpoint, or be charged against another host's rate-limit gauge. `429 Too Many Requests` is treated as an infra failure (not a 4xx caller error) so the breaker actually opens against secondary rate-limits and avoids escalating bans.

- **Case-insensitive Bearer scheme.** Per RFC 7235 §2.1, `Authorization: bearer ...` and `BEARER ...` are accepted alongside `Bearer ...`, so callers behind proxies that normalise the scheme are not spuriously rejected.

- **Bounded token cache.** Keymint caches up to 1,024 installation tokens.
  It keys cached tokens by normalized scope and the mounted PEM's content hash.

- **RSA App private keys.** GitHub App JWTs require RS256. PKCS#1 and PKCS#8 RSA keys are accepted; other App key types are rejected. Sparkle release signing continues to use Ed25519.

- **Trusted-proxy-aware client IP extraction.** Set
  `trusted_proxies:` in the config to a list of CIDR blocks for your
  Ingress controller / API gateway / mesh sidecar. When the
  immediate peer is in one of those blocks, keymint walks the
  `X-Forwarded-For` chain right-to-left (then falls back to
  `X-Real-IP`) to recover the real client IP for the per-IP rate
  limiter. Include only addresses assigned to proxies that sanitize incoming
  forwarding headers. An empty list uses the immediate peer address.

  ```yaml
  trusted_proxies:
    - 10.0.42.7/32      # specific ingress proxy
    - 192.168.1.5/32    # specific load balancer
  ```

- **Stale-but-valid token fallback.** If a synchronous refresh
  fails (GitHub timeout, 5xx) but the previously-cached token
  still has any validity left, keymint logs the failure and hands
  back the cached token instead of failing the request. Callers
  get a usable token; the next call retries the refresh.

## Observability

Service mode emits JSON request logs by default. Use `--log-level` to adjust
verbosity and `--log-human` for human-readable output. Installation-token
logs identify issued credentials by SHA-256 fingerprint.

Set `OTEL_EXPORTER_OTLP_ENDPOINT` for OTLP gRPC tracing or
`OTEL_TRACES_EXPORTER=console` for local inspection. Incoming HTTP trace
context is carried into outbound requests without forwarding baggage.

Scrape Prometheus metrics from the separate listener configured with
`--metrics-listen` (default `:9100`). The HTTP metric series record bounded
route labels, method, status, latency and in-flight requests. Additional metrics
cover installation-token exchanges, TokenReview, temporary credential cleanup,
and Telegram enrollment. Scope the
metrics listener to your monitoring namespace with a NetworkPolicy.

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

### Restricted OAuth emergency sessions

`POST /emergency/sessions` accepts an optional `scopes` array. Nonempty scopes
must be an exact subset of the allowed `github_user` profile's configured OAuth
scopes; other providers and additional permissions are rejected before device
authorization starts. For example, an administrative profile containing `repo`,
`workflow`, and `admin:org` can issue a session requesting only `repo` and
`workflow`, using the same OAuth application and workload allowlist. Omit the
field to retain the configured profile's normal permissions.

The session exposes any explicit restriction as `scopes`. Every GitHub user
session checks that the scopes returned by GitHub match the requested scopes
or, when omitted, the profile scopes. On mismatch, Keymint rejects the grant
and attempts token revocation. This prevents prior OAuth authorizations from
silently broadening a request. Configure scope lists in
[GitHub's normalized form](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps#normalized-scopes)
by omitting scopes already implied by another entry. OAuth `repo` remains
a broad permission, not a per-repository restriction. Consumers must enforce
their own operation and repository approvals and must not reuse a broader session.

### Release-key destination lookup

Release-key policy binds an exact repository allowlist, a trusted GitHub API
installation (`github_key`), and permitted `secret_scopes`. Omitted scopes default
to `[repository]`; organization storage requires explicit opt-in:

```yaml
release_keys:
  internal-signing:
    kind: sparkle_ed25519
    github_key: release-lookup
    secret_scopes: [repository, organization]
    private_key_file: /run/release-keys/internal-signing
    repositories: [example-org/example-app]
    secret_name: SPARKLE_EDDSA_PRIVATE_KEY
```

`release-lookup` must reference a configured `keys` entry. For repository secrets,
the broker mints a repository-scoped installation token with `secrets: read` and
fetches `/repos/{owner}/{repository}/actions/secrets/public-key`. For organization
secrets, it uses the active GitHub-user emergency session to fetch
`/orgs/{owner}/actions/secrets/public-key`. The session must have the GitHub grants
needed for that operation (`admin:org`, plus `repo` for private repositories).
Kubernetes-backed sessions cannot authorize organization lookups. A restricted
session cannot inherit broader organization permissions from its profile. GitHub device authentication uses github.com. Organization lookups require a
github.com installation API, while repository lookups can use an Enterprise
installation API.

Clients submit `github_owner`, `github_repository` and `secret_scope` to
`POST /emergency/sessions/{id}/seal-release-key`. Scope is `repository` or
`organization`; omission retains repository behavior for existing clients. The
repository remains mandatory for organization secrets because release policy
authorizes an individual project. Unknown scopes, disabled destinations and
unlisted projects fail closed. Each repository and scope pair can bind to one
release key. The broker fetches the encryption key over HTTPS,
rejects redirects, and rechecks authorization after lookup before reading signing
material. Optional legacy `destination_key_id` and `destination_public_key`
fields must match the broker lookup; callers cannot choose an arbitrary key.

The response binds `secret_scope`, `github_owner` and `github_repository` to the
`destination_key_id` and `encrypted_value`. Consumers must verify that complete
binding before writing the ciphertext to the matching GitHub endpoint. Padd
performs this check and maintains selected-repository access for organization
secrets. The broker's project allowlist does not itself change GitHub's secret
access policy.

Deploy the updated Keymint before the updated Padd client. Enable organization
scope in deployment config before using the new organization branch. Older
Padd repository requests remain supported; the new client rejects old unbound
broker responses. Organization lookup reuses the existing GitHub break-glass
session and does not require an additional organization permission on the App.
Repository lookup still needs the existing App Secrets-read grant. Configure and
approve any missing GitHub grants before operational acceptance.

### Service preflight

Run validation with the same mounted files the service will use. YAML
validation rejects unknown fields. Service validation checks mounted signing
keys, file-backed authentication settings, Telegram relay keys, and configured
passkey IDs. Use `--against` with the currently running configuration to check
restart-only settings before a hot reload.

```sh
keymint validate --service --config candidate.yaml
keymint validate --service --config candidate.yaml --against current.yaml
```

Preflight uses local files and leaves service state intact. GitHub grants,
Kubernetes RBAC, and network reachability require deployment checks.

### Emergency cleanup storage

Service deployments with emergency profiles must configure
`emergency_state_file` on persistent storage. Keep its adjacent `.cleanup-key`
file with the database, restrict both to the broker identity, and run one
replica. Live authorization remains memory-only, but encrypted revocation
records survive restart until remote cleanup succeeds. The event stream never
contains tokens or revocation secrets. Losing either persistent file prevents
reliable cleanup. Retain both during upgrades and recovery. Restart makes
outstanding cleanup due immediately and preserves the original age of overdue
records. OAuth cleanup uses the GitHub identity captured at exchange, including
after mounted files rotate. A 404 from GitHub's token revocation endpoint
confirms that the token is already absent.

For Kubernetes upgrades, keep one process owning this volume, including while
old and new pods transition. A `Recreate` Deployment strategy avoids overlapping
replicas. When migrating an existing `RollingUpdate` Deployment, clear
`spec.strategy.rollingUpdate` in the same atomic patch that selects `Recreate`;
omitting it from a server-side apply can retain the old field and reject the
upgrade. Verify file permissions after remounting the volume: the generated
cleanup key must remain owner-only.

Use `keymint cleanup-status --state-file /path/to/state.db` to list pending
session IDs and quarantined IDs with their timestamps. The command reads
metadata only and works without the cleanup encryption key.

If a cleanup record cannot be decrypted or repeatedly fails remote revocation,
use the session ID in the cleanup error to identify it. Restore the original
cleanup key when available. To recover service while preserving the encrypted
records for investigation, stop Keymint, back up the state database and its key,
and run one of the following on the mounted state volume.

```sh
keymint cleanup-quarantine --state-file /path/to/state.db --session-id SESSION_ID
keymint cleanup-quarantine --state-file /path/to/state.db --all
```

Use `--all` only when all outstanding records need quarantine, for example
after losing the cleanup key. If an unusable key file remains, archive it
before restarting so Keymint can generate a new one. Quarantine preserves the
event journal and removes the selected records from automatic revocation and
its pending-cleanup metrics. Any credential left active can still be used
until it expires or is revoked. Revoke affected OAuth grants or delete affected
Kubernetes bound Secrets separately.

### Passkey inventory and profile scoping

Passkey enrollment accepts an optional `label` beside `proof_session_id` in
`POST /emergency/passkeys/enrollments`. Enrollment still requires an active
TOTP proof. The inventory shows labels, stable credential IDs, and any stored
clone warning.

```sh
keymint passkeys list --state-file /path/to/passkeys.json
keymint passkeys revoke CREDENTIAL_ID --state-file /path/to/passkeys.json
```

Stop Keymint before revoking a passkey. Replace its ID in any scoped profiles
before restarting, or remove access to the affected profiles. A profile with
no usable matching credentials cannot start a WebAuthn ceremony. Set
`passkey_credentials: [CREDENTIAL_ID]` under any WebAuthn emergency or approval
profile to restrict eligible credentials. For Telegram enrollment, set it
on the relay's approval profile. Existing profiles without this setting
continue to use the shared passkey inventory.

### Journal retention

Set `emergency_journal_retention: 720h` alongside `emergency_state_file` to
prune terminal session histories and their approval rows 30 days after the
last event. The minimum duration is `24h`. The janitor retains live sessions
and sessions with pending cleanup records. Quarantined cleanup records are
managed separately. Retention is disabled by default. SQLite can reuse freed
pages for later events.

Before enabling retention, verify that event consumers handle
`history_truncated: true` on `GET /emergency/events`. It signals possible gaps
before the supplied cursor. Reconcile outstanding session state, process the
retained events, and continue from `next_cursor`. Export the journal separately
if audit policy requires a longer history.

### Emergency lifecycle and consumer compatibility

A session begins in `awaiting_github`, `awaiting_totp` or `awaiting_passkey` and
becomes `active` only after verification and durable activation audit succeed.
Explicit revocation first enters `revocation_pending`, which immediately denies
credential access while external cleanup runs. `DELETE /emergency/sessions/{id}`
returns HTTP 502 if cleanup fails and remains pending, HTTP 404 if the session
is unavailable, or HTTP 503 if Keymint otherwise cannot confirm the revocation.
The broker retries pending cleanup once per prune pass and publishes
`session.revoked` after cleanup succeeds. `revoked`, `expired`, and
`invalidated` are terminal states. Profile revisions are immutable within a
session. Removal or changed authority invalidates it.
The broker allows up to 16 sessions per workload identity and 1024 overall,
including creations in progress. A Kubernetes credential reports the earlier
of the token and session expirations.

TOTP allows five attempts per 30 seconds and up to ten failures per secret
over a 24-hour window starting with its first failure. The budget survives
broker restarts and is shared by every profile using that secret. After the
limit is reached, authentication resumes when the window ends or an operator
rotates the secret. Monitor `keymint_operations_total{operation="totp_verify",outcome="error"}`
for rejected verifications.

Lifecycle events include `session.revocation_pending` and `session.revoked`.
Consumers must treat pending revocation as loss of authority and reconcile stale
bindings after restart or journal replacement. See
[ADR 0003](docs/adr/0003-publish-durable-emergency-session-events.md). Enrolling a
passkey requires a still-active TOTP proof when enrollment finishes, not just
when its ceremony starts. Keymint rejects assertions with a WebAuthn clone
warning and records the warning in the passkey inventory. Flagged credentials
stay blocked across restarts. Replace them through the TOTP-backed enrollment
flow.

Padd chooses organization storage for its shared-secret path and repository
storage for private repositories in Free-plan organizations. Both use the same
explicit target contract and broker-resolved encryption keys. Successful startup
is separate from live signing bootstrap, remote cleanup recovery and
observability delivery; verify those operations after the coordinated rollout.

## License

MIT — see [LICENSE](LICENSE).

### Approval-only emergency sessions

An `approval` emergency profile uses `authentication: webauthn` and grants one
redemption of a caller-bound request without issuing a platform credential.
Allowlist the profile for the trusted workload that creates and redeems
requests. Send the SHA-256 `approval_digest`, an owner-facing single-line `approval_label` of up to 3000 bytes
and optional `ttl_seconds` from 300 to 3600 to `POST /emergency/sessions`.
Omit the TTL for five minutes. Approval profiles allow up to one hour by
default, and `max_ttl` can set a lower ceiling. Include the
task identity, request ID and operation policy in the digest. The passkey
ceremony returns the review label and expiry so the user can review the
action before authenticating. The approval keeps the expiry set at session
creation, including the time spent waiting for passkey verification.

After verification, send the same digest to
`POST /emergency/sessions/{id}/redeem-approval` as the same workload.
A successful redemption returns HTTP 204 and records consumption in the
durable emergency journal. Expiry, revocation and restart invalidate live
grants. The calling workload owns task authentication, upstream dispatch
and receipt recovery.
