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
- [ ] 20 Add regression coverage for emergency HTTP routes, passkey verification, startup/cache orchestration, and failure/interleaving cases; run final race tests, vet and vulnerability scan.

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
