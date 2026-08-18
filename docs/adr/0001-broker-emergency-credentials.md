# Broker emergency credentials in Keymint

Keymint owns human re-authentication, short-lived credential issuance, expiry,
revocation, and audit for emergency sessions. Callers retain operation semantics
and receive credentials only in trusted process memory; credentials are never
placed in an agent workspace, environment, or conversation. GitHub uses an OAuth
App device flow with explicit scopes and validates the immutable user ID, while
Kubernetes supports either TOTP or GitHub device authentication before issuing
a Secret-bound TokenRequest token. Authentication method and credential provider
are separate; TOTP remains the external-service-independent fallback. Deleting
the bound Secret revokes the Kubernetes session.

GitHub OAuth tokens do not expire with the local 15-minute session. Keymint
therefore holds the OAuth App client secret and revokes the token at GitHub on
session expiry, explicit revocation, or profile removal.

Session state is memory-only: broker restart invalidates it, so deployments with
emergency profiles run one replica. Add an encrypted shared session store only
if failover during a 15-minute emergency session becomes a measured need.
