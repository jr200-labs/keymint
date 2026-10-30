# Keymint review remediation

Review baseline: `dfc5c46fa761c4c956750f140fdbc720ac5c7887`.
Work through items in order. Check an item only after its focused verification
passes; record implementation and evidence below. Priorities describe the review
findings, not a claim that deployment has been changed.

## Checklist

- [x] 01 P1 Bind release-key encryption to a broker-resolved GitHub repository public key; reject caller substitution.
- [x] 02 P1 Recover remote credential cleanup after graceful shutdown and crash; metadata invalidation alone does not revoke OAuth credentials.
- [x] 03 P1 Retain failed profile-removal revocations for retry with their original profile.
- [x] 04 P1 Serialize OAuth polling transitions and reject/revoke late results after revocation or expiry.
- [x] 05 P1 Bind sessions to immutable profile revisions; invalidate changed authority and revalidate creation across reload.
- [x] 06 P2 Enforce TOTP attempt limits and successful-timestep replay prevention across sessions.
- [x] 07 P2 Retain cleanup ownership of partially-created Kubernetes binding Secrets.
- [x] 08 P2 Match credential-helper destinations by exact hostname and permitted scheme, not substring.
- [x] 09 P2 Commit lifecycle events consistently with state; fail activation closed and record terminal revocation state.
- [x] 10 P2 Reconcile PEM watchers and Kubernetes issuer availability on configuration reload.
- [x] 11 P2 Restrict GitHub App JWT signing to supported RS256; retain Ed25519 only for release signing.
- [x] 12 Instrument every emergency route and its authentication, including denied/error outcomes.
- [x] 13 Record GitHub exchange latency and clock-offset metrics at their actual observation sites.
- [x] 14 Extract inbound trace context, trace outbound dependencies, and correlate logs with traces.
- [x] 15 Use the configured zap logger consistently for emergency lifecycle failures.
- [x] 16 Measure refresh/fallback, revocation backlog, journal failure, and configuration reload outcomes with bounded labels.
- [x] 17 Centralize emergency lifecycle transitions, pending external operations, profile revisions, and terminal-state guards in an explicit state model.
- [x] 18 Extract mint caching, refresh/cooldown, and PEM-watch lifecycle from Cobra into a testable module with Mint/Reload/Close.
- [x] 19 Unify request authentication, TokenReview caching, rate limiting, and telemetry behind one module.
- [x] 20 Add regression coverage for emergency HTTP routes, passkey verification, startup/cache orchestration, and failure/interleaving cases; run final race tests, vet and vulnerability scan.

## Baseline verification

- Existing `go test -race -cover ./...` and `go vet ./...` passed.
- Overall statement coverage was 49.8%; emergency HTTP handlers, passkey
  verification and command orchestration had no coverage in that run.
- Temporary tests reproduced OAuth completion after revocation, profile
  retargeting, substring-host matching, missing emergency telemetry, and missing
  inbound trace propagation.
- `govulncheck` found no reachable known vulnerabilities. Three module-level
  advisories concerned packages not imported by this binary.
- Live infrastructure and externally maintained reusable workflows were not
  exercised. Local tests do not prove deployed RBAC, TLS, network policies or
  GitHub permissions.

## Completed work and evidence

Implementation notes and focused checks are added here as each item completes.

### 01 Repository-bound release encryption

Added required `release_keys.*.github_key`, authenticated repository-scoped
public-key lookup over HTTPS with redirects disabled, and mismatch rejection
before reading signing material. Legacy destination fields remain accepted only
when they match the trusted lookup. Verification: race-enabled releasekey,
config and server tests, including an HTTP-handler substitution regression.

### 02 Restart-safe credential cleanup

Added an AES-GCM encrypted cleanup table alongside the credential-free event
journal. Credentials are tracked before delivery; OAuth cleanup captures its
original application identity. A mode-0600 key next to the state database must
persist with that database. Startup retries restored cleanup, and graceful
shutdown attempts every outstanding revocation. Service mode now requires a
persistent emergency_state_file when emergency profiles are enabled. Tests
simulate crash recovery, transient upstream failure, ciphertext storage, and
shutdown with unexpired credentials (`go test -race ./internal/emergency
./internal/server`). External exchange and local persistence cannot be one
transaction; failures before durable staging never deliver a credential.

### 03 Retry profile-removal revocations

Removed sessions no longer discard cleanup ownership. The cleanup worker retries
records with no live session immediately, using their persisted original
identity, regardless of original expiry. Verified profile removal during a 503
followed by successful janitor retry (`go test -race ./internal/emergency`).

### 04 Guard OAuth polling transitions

A per-session polling reservation prevents overlapping exchanges. Completion
checks the exact live session and expiry before publishing activation; obsolete
results are revoked using tracked cleanup. The deterministic blocked-exchange /
concurrent-Revoke reproduction is now a passing regression under `-race`.

### 05 Immutable session authority

Sessions capture the original profile. Reload invalidates sessions whose profile
changes, and session creation checks the configuration revision and allowlist
again before publication. The profile-retarget reproduction now asserts denial
without invoking the new issuer. Race-enabled emergency/server tests pass.

### 06 TOTP identity protection

A durable secret-identity budget allows five verification attempts per 30-second
window across all sessions/profiles. A persisted accepted-step watermark rejects
replay, including after restart. Empty/short secrets are rejected. Verified
replay and budget regressions plus race-enabled emergency/server tests.

### 07 Partial Kubernetes issuance cleanup

Reserve and persist the binding Secret identity before creating it. Retries reuse
that identity, partial failures retain it, and deleting an absent Secret is
idempotent. Device-authenticated Kubernetes sessions retain both OAuth and Secret
cleanup. Verified failed issuance, repeated retry, and explicit cleanup under
race-enabled emergency/server tests.

### 08 Exact credential destinations

Credential routing now compares parsed hostnames and ports to the configured
GitHub endpoint, supports only HTTPS/SSH URL parsing, and the credential helper
emits credentials only for HTTPS. Verified sibling-host, plaintext, public-host
cross-routing and port mismatch rejection with race-enabled config/helper tests.

### 09 Ordered durable lifecycle events

Creation and activation journal before publishing authority while holding the
session lock. Failed activation remains unauthorized. Explicit revocation emits
a terminal Revoked state and retains a denied session if its event needs retry.
Expiry journal failures remain denied and retryable. SQLite-trigger failure and
revocation/restart regressions pass in race-enabled emergency/server tests.

### 10 Reload resource reconciliation

PEM watchers synchronously reconcile added/removed directories before config
publication and close with the service. Kubernetes issuance is initialized even
when no Kubernetes profile exists yet. Changes to audience, passkey or journal
settings explicitly require restart instead of silently retaining stale
resources. Verified newly-added PEM rotation plus race-enabled command,
server and emergency tests.

### 11 Supported GitHub JWT algorithm

App key parsing and signing reject Ed25519; RSA PKCS#1/PKCS#8 and RS256 remain
supported. Sparkle Ed25519 sealing is unchanged. Verified rejection, RSA minting
and release-key tests with the race detector.

### 12 Emergency route instrumentation

Shared HTTP middleware now records bounded route/method/status counts, duration,
in-flight work and spans for all routes, including denied and unmatched requests.
Emergency authentication records actual TokenReview outcomes and cache lookups.
Verified success/rejection counters and race-enabled server/metrics tests.

### 13 Real exchange and drift observations

GitHub exchanges report transport/HTTP outcomes and duration; parsed Date headers
report actual clock offset. Both metrics identify the configured API endpoint.
A 503 response regression verifies observation on failure as well as success;
race-enabled mint, metrics and command tests pass.

### 14 Distributed trace continuity

Inbound middleware extracts trace context. GitHub, Kubernetes, OAuth and release
key lookups use client spans and propagate context; response-body closure ends
the client span. Attributes omit URLs, headers and bodies. Completion logs carry
trace/span IDs and bounded routes. Incoming/outgoing propagation regressions and
all internal race-enabled tests pass.

### 15 Consistent and redacted logging

Emergency lifecycle errors use the configured zap logger and handler logs carry
trace correlation. Raw upstream error bodies are no longer exposed in responses
or logs. A zap observer verifies cleanup errors use the configured logger;
race-enabled emergency, server and mint tests pass.

### 16 Internal failure and backlog signals

Added bounded operation outcomes/durations for token refresh, fallback, config
reload, durable journal writes and credential revocation. Cleanup gauges expose
tracked, due and overdue work; breaker gauges identify each endpoint. Failure
injection verifies journal/revocation error counters and due backlog. Full race
suite and the focused observability regression pass.

### 17 Explicit lifecycle and operation states

Central transition guards prevent terminal-state reactivation and pair event
names with states. Revocation first denies local access through
revocation_pending. Context-aware per-session gates serialize polling, issuance
and revocation; network work releases the global registry lock. Reload and
shutdown invalidate in-flight work, whose results cannot restore authority.
Tests cover terminal guards, concurrent OAuth/revocation serialization, unrelated
session progress during blocked issuance, and invalidation of late issuance.
Race-enabled emergency/server tests pass. Public session copies discard private
profile and operation metadata.

### 18 Installation-token broker module

Moved caches, freshness states, singleflight, bounded cooldowns and reconciled
PEM watchers into internal/broker with Mint/Reload/Close. Refreshes have at most
one background worker per cache entry and shutdown cancels outstanding work.
Clock and exchange seams support interface-level tests. Verified coalesced
misses, scope separation, valid/expired fallback, refresh cooldown, rotation and
shutdown cancellation under the race detector; the full suite passes.

### 19 Shared authentication module

Mint and emergency handlers use one authenticator for bearer parsing, trusted
proxy handling, two-tier limits, coalesced TokenReview/cache access, error
classification, tracing and metrics. Mint authorization uses one immutable
configuration snapshot. Verified one TokenReview across both route families,
existing auth failure/cache/rate-limit regressions, and race-enabled tests.


### 20 Regression suite and final verification

Added authenticated/denied HTTP coverage across every emergency API route,
synthetic WebAuthn registration and signed assertions, wrong-origin rejection,
and revoked enrollment-proof rejection. Startup tests enforce durable emergency
storage; broker tests cover the extracted cache/startup orchestration. Final
hardening disables HTTP response caching and log sampling, observes panics,
bounds reload cleanup, and joins janitors/watchers before closing resources.
Expired-session cleanup clears credentials after successful revocation.

Final verification:

- `go test -race -coverprofile=/tmp/keymint-remediation-coverage.out -timeout=10m ./...`: pass.
- Overall statement coverage: **66.1%**, up from 49.8%; broker 80.6%, emergency
  73.7%, server 77.4%. This is regression coverage, not proof of every branch;
  Cobra command entrypoints and live service startup retain limited coverage.
- `go vet ./...`: pass.
- Shared golangci-lint configuration: **0 issues**. Used the broker-attached
  github-action-templates configuration locally instead of Makefile's remote
  curl sync; no shared workflow or configuration files were changed.
- `CGO_ENABLED=0 go build -o /tmp/keymint-review ./cmd/keymint`: pass.
- `govulncheck@v1.9.0 -show verbose ./...`: no affected code or imported
  packages. Module-only advisories GO-2026-6866, GO-2026-6860 and GO-2026-5932
  concern packages this binary does not import; dependencies were not upgraded.
- `git diff --check`: pass. Root `preview-checkpoint.json` is absent, so no
  checkpoint command is declared.

Deployment migration: configure `release_keys.*.github_key` with scoped GitHub
Secrets read access; persist `emergency_state_file` and its adjacent mode-0600
`.cleanup-key` together, with one service replica owning the store. Audience,
passkey and journal changes require restart. Update dashboards for endpoint
labels on latency/clock metrics and the new revocation-pending lifecycle state.
Live GitHub/Kubernetes, physical passkeys, exporter delivery, deployed network
policy/RBAC, and external reusable workflow execution remain deployment checks.


## Deployment evidence and closeout (2026-10-30)

The original 20 review items above are implemented and released in v1.8.1
(Keymint PRs #118 and #119). IaC PR #2387 supplied the installation binding,
Secrets-read desired grant, persistent-store guidance and Recreate strategy;
Janeway audit PR #3 is merged. IaC PR #2388 selected v1.8.1.

An existing RollingUpdate Deployment retained its defaulted rollingUpdate field
under server-side apply. A local Kubernetes API reproduction rejected both an
omitted field and an SSA null with the exact production validation error. An
atomic merge patch setting Recreate and clearing rollingUpdate succeeded; later
SSA reconciles succeeded. The same UID- and resource-version-guarded patch was
dry-run validated, applied through Padd breakglass, and verified on the cluster.

Delivery C-01M651FJ072BXDJ6Y21GG72RGM succeeded on 2026-10-29 at 23:56 UTC.
Helm release revision 157 was deployed. Deployment generation 39 was observed,
with one updated/available/Ready replica of ghcr.io/jr200-labs/keymint:v1.8.1
(image digest sha256:4703e4b76807ebd28bf617e8f23e17365d1bca217035689aea0e9694ba1617f2).
The pod had zero restarts at rollout verification and remained Ready at this
closeout check. These are dated rollout observations, not proof of all external
operations.

### Organization-secret integration follow-up

- [x] 21 Support both organization and repository Actions secret destinations
  through a broker-verified target. Implementation and verification are recorded
  below; deployment of this follow-up is separate from the v1.8.1 rollout above.

The follow-up adds an explicit secret scope, repository-default policy with
organization opt-in, and a trusted resolver for both GitHub endpoints. Repository
lookups retain scoped App authority; organization lookups reuse the active GitHub
user session with matching API authority. Padd no longer fetches encryption keys
or supplies recipients; it verifies the broker's scope/owner/project binding
before writing ciphertext. Configuration, rollout order and the decision are
recorded in ADR 0004. Verification: full Keymint race suite, full Padd suite, targeted Padd race
tests for keymint/emergency/scotty/tools, vet, lint (0 issues for both binaries)
and production builds pass. Crypto tests decrypt only with the intended
repository/organization key. Regressions reject substituted recipients,
unapproved scopes/projects, revoked sessions, changed config, different API
authorities, scope-restricted sessions, redirects, invalid public-key metadata and old unbound responses.
Lookup and sealing outcomes are observed, including denied/error cases.
The production configuration passes Keymint validation; four invalid policy
fixtures are rejected, and organization-only policy does not require App
Secrets permission. Production Kustomize rendering, relative documentation
links and diff checks pass. Root preview checkpoint manifests are absent in all
three changed repositories. The implementation was released in v1.9.0 and
deployed with the matching consumer as recorded below.

Live owner acceptance of GitHub App grants, end-to-end signing bootstrap,
restart cleanup recovery, physical-passkey acceptance, exporter delivery and
alert routing were not independently verified by the rollout. The HTTP/race
regressions cover those application boundaries locally. This record does not
claim operational acceptance for those external checks.


### Organization-secret rollout completion

Keymint PR #122 and release PR #123 published v1.9.0. The matching consumer
release is Padd v0.2.176. IaC PR #2393 enabled the reviewed organization policy,
and IaC PR #2397 selected Keymint v1.9.0. The live release-key configuration
permits both repository and organization secret destinations.

Delivery C-01M65CTABFTEA243N7SA1KRNHD succeeded on 2026-10-30 at 03:16 UTC.
Helm release revision 158 is deployed. Keymint Deployment generation 40 is
observed with one updated/Ready v1.9.0 replica, Recreate strategy and zero pod
restarts. The running image digest is
sha256:3b75277bba2a1bc7566bde67fe4c33cf7f1de5f5d14945c9a044409ae9280fe8.
The consumer Deployment generation 367 is observed with one updated/Ready
v0.2.176 replica.

An earlier successful reconciliation still had v1.8.1 running; completion was
accepted only after checking the actual image against the authoritative IaC pin
and live Helm values. All 21 implementation items are checked off and the
matching versions are now deployed. No live GitHub secret was rewritten for
verification; end-to-end bootstrap and other external acceptance limits above
remain distinct from the verified rollout.
