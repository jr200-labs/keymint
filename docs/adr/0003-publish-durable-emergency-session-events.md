# Publish durable emergency-session events over HTTP

Status: Accepted

## Context

Live session authorization remains in Keymint process memory. The separate
encrypted cleanup table retains revocation material as described in
[ADR 0001](0001-broker-emergency-credentials.md#recovery-amendment-from-the-security-review).
Expiry, explicit revocation, profile removal, and process restart can therefore
change a session without a request from its consumer. Polling every session
either delays cleanup or creates unnecessary traffic, while an external message
broker would add an operational dependency for the current single producer and
consumer.

## Decision

Keymint records emergency-session lifecycle events in an embedded SQLite
journal and exposes them through the authenticated
`GET /emergency/events?after=<cursor>&wait=30s` endpoint. The request waits for
an event or the bounded timeout and returns up to 100 events plus an opaque
resume cursor.

The cursor includes a persistent stream generation. Consumers that reconnect
after a journal replacement automatically replay the new stream from its
beginning. On startup, Keymint publishes `session.invalidated` for unfinished
sessions from the previous process because live authority is never restored.
It separately retries encrypted cleanup for those sessions.

Events contain session identifiers and lifecycle metadata only. Credentials,
OAuth device codes, passkey ceremony tokens, and bearer tokens are never
written to event rows. The same database also contains the separately encrypted
cleanup table; the database file and its backups therefore require credential
protection. Activation events commit before authority is granted. Withdrawal
fails closed even if its event write fails and needs retry.

Explicit revocation emits `session.revocation_pending` before remote cleanup and
`session.revoked` after successful cleanup. Pending revocation denies credential
access immediately; consumers must not treat it as active. Expiry and profile
invalidation similarly withdraw authority while failed remote cleanup remains
tracked for retry. Terminal states never reactivate.

## Consequences

Consumers receive changes promptly and resume after transient disconnects
without running NATS or another service. SQLite keeps Keymint a self-contained
single process and gives the stream the same persistence model as its other
local security state. Consumers must still reconcile periodically to cover
implementation defects and storage loss. A future need for multiple producers,
independent consumer groups, or cross-region delivery would require revisiting
the transport.
