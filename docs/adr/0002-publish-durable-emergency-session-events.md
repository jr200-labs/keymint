# Publish durable emergency-session events over HTTP

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
written to the journal. A broker is unnecessary for the current single Keymint
producer and Padd consumer; consumers must still reconcile periodically to
cover implementation defects and storage loss.
