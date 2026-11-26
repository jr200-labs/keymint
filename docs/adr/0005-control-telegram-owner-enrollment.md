# Control Telegram owner enrollment from Keymint

Keymint owns operator approval, QR presentation and access to the encryption key
for an isolated Telegram relay. Telegram authorizes an MTProto client at the
account level. The relay completes Telegram login and verifies the configured
account ID. It holds the MTProto session, enforces the message and topic
allowlists, and stores session state as ciphertext.

Each configured relay binds a name, immutable Telegram account ID, passkey
approval profile, operator workload subject, relay workload subject and HTTPS
origin. Keymint creates its own review label and approval digest. It requires
the same operator subject and active, exact approval for every enrollment
request. Starting the enrollment redeems the approval. The relay stages the
new session in memory until Keymint authorizes commit. It expires abandoned
enrollments and attempts to log out the provisional Telegram session.

Keymint reads two distinct 32-byte keys from base64-encoded Secret-mounted
files. It releases the wrapping key only to the configured relay's
audience-bound Kubernetes ServiceAccount. The relay keeps it in process memory.
The control key authenticates Keymint to the fixed relay HTTPS origin. Mount it
only in Keymint and the relay. The enrollment endpoint accepts only the
configured owner ID and bounded requests. Keep the relay control endpoint and
Keymint's API on private, trusted HTTPS networks.

QR tokens, Telegram two-step passwords and MTProto session material stay out
of Keymint's journal. The existing emergency approval journal stores approval
IDs, workload subjects, review labels, digests, timestamps and state.
An interrupted ceremony requires a new passkey approval after expiry. Check
Telegram's active sessions and revoke an abandoned authorization if the relay
exited before it could log out. Removing the Keymint binding blocks new relay
key retrieval and enrollment; revoke the active Telegram session to terminate
an already-running authorization. Preserve the wrapping key with the encrypted
session. Retire and re-enroll the session when replacing the key.

## Operator interface

Configure `telegram_relays` in service mode. Each entry needs `owner_id`,
`operator_subject`, `approval_profile`, `relay_subject`, `url`,
`control_key_file` and `wrapping_key_file`. Use a dedicated relay identity
and a `provider: approval`, `authentication: webauthn` profile allowed to the
trusted operator subject. Use independent keys per relay. Keymint requires
audience-bound TokenReview and its durable emergency state store.

Use the Keymint CLI from a private interactive terminal with the configured
operator workload's audience-bound token file.

```sh
keymint telegram-enroll owner-relay --url https://keymint.example --token-file /path/to/operator-token
```

The command displays the passkey verification link and then the Telegram QR. It commits after the relay
confirms the authorized Telegram account matches policy.

An authenticated operator client starts at `POST /telegram-enrollments/{relay}`.
It opens the response's `verification_uri` in the existing passkey flow. After
approval, it uses `/telegram-enrollments/{relay}/{id}` with these suffixes.

| Request | Behavior |
| --- | --- |
| `POST /start` | Start or recover the same approved enrollment. |
| `GET /status` | Await `qr`, `password_required`, or `verified`. |
| `GET /qr` | Display the current QR PNG privately. Refresh after it expires. |
| `POST /password` | If requested, submit a Telegram two-step password as `{"password":"…"}` over HTTPS. |
| `POST /commit` | Persist the verified session. Use status to confirm `enrolled`. |
| `POST /cancel` | Cancel an enrollment before committing. |

The relay requests its wrapping key via
`GET /telegram-relays/{relay}/wrapping-key`. Its projected ServiceAccount
token must target Keymint's configured audience. The response is exactly
32 bytes and uses `Cache-Control: no-store`. Operator clients and agent
workloads have no access to this endpoint for that relay.

## Observability

Keymint exposes `keymint_telegram_requests_total{action,outcome}` and
`keymint_telegram_request_duration_seconds{action}` on its Prometheus
listener. The action label covers approval, start, status, QR, password,
commit, cancel, and wrapping-key requests. The outcome distinguishes
authorization or approval errors, relay conflicts, relay timeouts and
connection errors, malformed relay responses, and QR failures. A successful
request means the action returned a response. Look for state `enrolled`
in a commit or status observation to confirm completion.

Structured milestone and failure logs include `enrollment_id` when Keymint
has resolved an authorized enrollment. That field matches the approval
session ID in the emergency journal. Routine successful polls appear in
HTTP request logs, with the bounded relay state available on the request
span. When OpenTelemetry is enabled, Keymint propagates trace context to
the relay and records the outbound HTTP status or transport failure.

Metrics use fixed action and outcome labels. Telemetry excludes passwords,
QR contents, key material, and relay payloads.
