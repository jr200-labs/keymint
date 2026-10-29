# Keymint review remediation

Review baseline: `dfc5c46fa761c4c956750f140fdbc720ac5c7887`.
Work through items in order. Check an item only after its focused verification
passes; record implementation and evidence below. Priorities describe the review
findings, not a claim that deployment has been changed.

## Checklist

- [ ] 01 P1 Bind release-key encryption to a broker-resolved GitHub repository public key; reject caller substitution.
- [ ] 02 P1 Recover remote credential cleanup after graceful shutdown and crash; metadata invalidation alone does not revoke OAuth credentials.
- [ ] 03 P1 Retain failed profile-removal revocations for retry with their original profile.
- [ ] 04 P1 Serialize OAuth polling transitions and reject/revoke late results after revocation or expiry.
- [ ] 05 P1 Bind sessions to immutable profile revisions; invalidate changed authority and revalidate creation across reload.
- [ ] 06 P2 Enforce TOTP attempt limits and successful-timestep replay prevention across sessions.
- [ ] 07 P2 Retain cleanup ownership of partially-created Kubernetes binding Secrets.
- [ ] 08 P2 Match credential-helper destinations by exact hostname and permitted scheme, not substring.
- [ ] 09 P2 Commit lifecycle events consistently with state; fail activation closed and record terminal revocation state.
- [ ] 10 P2 Reconcile PEM watchers and Kubernetes issuer availability on configuration reload.
- [ ] 11 P2 Restrict GitHub App JWT signing to supported RS256; retain Ed25519 only for release signing.
- [ ] 12 Instrument every emergency route and its authentication, including denied/error outcomes.
- [ ] 13 Record GitHub exchange latency and clock-offset metrics at their actual observation sites.
- [ ] 14 Extract inbound trace context, trace outbound dependencies, and correlate logs with traces.
- [ ] 15 Use the configured zap logger consistently for emergency lifecycle failures.
- [ ] 16 Measure refresh/fallback, revocation backlog, journal failure, and configuration reload outcomes with bounded labels.
- [ ] 17 Centralize emergency lifecycle transitions, pending external operations, profile revisions, and terminal-state guards in an explicit state model.
- [ ] 18 Extract mint caching, refresh/cooldown, and PEM-watch lifecycle from Cobra into a testable module with Mint/Reload/Close.
- [ ] 19 Unify request authentication, TokenReview caching, rate limiting, and telemetry behind one module.
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
