# Use WebAuthn for direct passkey authentication

Keymint is the WebAuthn relying party for direct passkey authentication and
delegates ceremony validation to `go-webauthn`. The browser may use any system
passkey provider, while Keymint persists only the public credential and
signature counter. Enrollment requires an active TOTP-authenticated emergency
session, and TOTP remains the recovery method if persistent passkey state is
lost or corrupted.

The ceremony runs at a configured public HTTPS origin that matches the relying
party ID; an internal caller may proxy that origin to Keymint but cannot perform
or weaken the ceremony. Short-lived one-time ceremony tokens travel in the URL
fragment so they are not sent in HTTP requests or referrer headers.
