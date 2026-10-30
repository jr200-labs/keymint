# Bind release sealing to explicit Actions secret destinations

Status: Accepted

## Context

Repository and organization Actions secrets use different encryption keys. A
repository-only broker cannot seal for Padd's shared organization-secret path.
Accepting a caller's arbitrary recipient would expose the mounted signing key
to a destination that release policy never authorized.

## Decision

Model a destination as scope, GitHub owner and repository. Repository remains
required even for organization scope because policy authorizes a project, not an
unrestricted organization export. Release-key configuration explicitly allows
secret scopes; omitted configuration preserves repository-only behavior.

Keymint owns target validation, trusted HTTPS lookup and sealing. Its githubsecret
module binds the selected target to the returned key, validates key metadata,
rejects redirects and never derives an authority from caller-supplied URLs.
Repository lookup uses a scoped installation token. Organization lookup uses the
active GitHub-user emergency session, with its original API authority checked
against the configured installation API, so OAuth credentials cannot cross hosts
or Enterprise API paths. No new organization-wide App permission is necessary.

The response echoes scope, owner and project alongside the encryption-key ID and
ciphertext. Padd uses a typed target and rejects missing or mismatched bindings
before any secret write. It retains responsibility for organization-secret
visibility and selected-repository access. No plaintext signing key crosses the
broker interface. Legacy key fields may only confirm the broker-resolved key;
they cannot select a recipient. Legacy repository requests remain supported.

Authentication and the configuration snapshot are checked again after lookup.
A failed or obsolete lookup must not reach signing material. Generic HTTP errors,
client spans, release_lookup/release_seal operation outcomes and scope-tagged completion logs
cover both destinations without logging OAuth credentials or signing material.

## Alternatives

Inferring scope from a caller-supplied key hides intent and reintroduces recipient
substitution. Granting every lookup App organization-wide Secrets access adds
permanent authority where an operation already requires a human GitHub session.
Duplicating lookup in Padd spreads key selection and rotation handling across two
services. An explicit target and one broker-owned resolver avoid those choices.

## Consequences and rollout

Deploy Keymint support and enable reviewed organization policy before upgrading
Padd. New Padd rejects older unbound responses; it never guesses a secret scope
or retries a denied organization request against a different endpoint. Existing
private-repository/Free-plan selection remains in Padd. Live GitHub grants and
end-to-end bootstrap require acceptance after deployment.

GitHub documents the required OAuth scopes and distinct endpoints in its
[Actions secrets API](https://docs.github.com/en/rest/actions/secrets#get-an-organization-public-key).
