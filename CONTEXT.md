# Credential Brokerage

Keymint holds credential-issuing authority and gives authenticated workloads
short-lived credentials without distributing long-lived signing material.

## Language

**Key**:
A GitHub App installation identity used for routine workload credentials.
_Avoid_: Account, user token

**Emergency profile**:
A configured human identity and credential provider that can be activated only
through explicit re-authentication.
_Avoid_: Admin key, permanent elevation

**Authentication method**:
The human-verification ceremony for an Emergency profile: TOTP, a WebAuthn
passkey, or GitHub device authentication. It is independent of the credential
provider.
_Avoid_: Provider, credential type

**Passkey credential**:
A WebAuthn public credential enrolled for direct human authentication. Its
private key remains in the person's chosen passkey provider.
_Avoid_: Bitwarden passkey, WebAuthn token

**Emergency session**:
A short-lived, revocable activation of one emergency profile by one authenticated
workload acting for a human.
_Avoid_: Break-glass token, login

**GitHub user session**:
A GitHub OAuth device-flow emergency session with explicit scopes and an allowed
immutable user ID.
_Avoid_: GitHub App installation token

**Emergency event journal**:
The embedded SQLite log of credential-free Emergency session lifecycle changes.
It supports replay and bounded HTTP long polling. Its event rows contain no
credentials or authentication ceremony material. The same SQLite database also
contains the separately encrypted cleanup records.

**Emergency event cursor**:
An opaque consumer position containing the journal stream generation and event
position. Consumers persist and return it unchanged.

**Cleanup record**:
Encrypted revocation material for an issued OAuth token or a reserved Kubernetes
binding Secret. Stored before credential delivery and removed only after remote
revocation succeeds. The original provider identity travels with the record;
restart retries cleanup without restoring session authority.

**Release-key destination**:
The allowlisted repository Actions encryption key fetched by the broker using
the configured GitHub App installation. It is distinct from the mounted release
signing key and from an organization Actions encryption key.
