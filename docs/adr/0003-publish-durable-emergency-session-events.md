# Publish durable emergency-session events over HTTP

Status: Accepted

## Context

Emergency credentials and live session state remain in Keymint process memory.
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
sessions from the previous process because credentials remain memory-only.

Events contain session identifiers and lifecycle metadata only. Credentials,
OAuth device codes, passkey ceremony tokens, and bearer tokens are never
written to the journal. The event write occurs as part of the session lifecycle
operation before that operation returns.

## Consequences

Consumers receive changes promptly and resume after transient disconnects
without running NATS or another service. SQLite keeps Keymint a self-contained
single process and gives the stream the same persistence model as its other
local security state. Consumers must still reconcile periodically to cover
implementation defects and storage loss. A future need for multiple producers,
independent consumer groups, or cross-region delivery would require revisiting
the transport.
