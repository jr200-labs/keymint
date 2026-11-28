# Keymint

Keymint brokers short-lived GitHub and Kubernetes credentials and seals release
signing keys for explicitly authorized GitHub Actions destinations. Read
[CONTEXT.md](CONTEXT.md) when changing credential or session semantics.

- Verify Rust changes with `make lint` and `make test`. Use `make build` to
  produce the native release binary.
- For changes to emergency authentication, cleanup, or storage formats, read
  the relevant [ADR](docs/adr) and exercise both successful authorization and
  denied access after expiry, revocation, or restart.
- Configure shared workflows in `.github/.shared-config.yaml` and regenerate
  them with `scripts/sync-shared`. Use the strict drift check to verify the
  generated files.
- Use Conventional Commits. Release Please advances the version and the
  shared Docker workflow publishes the image to `ghcr.io/jr200-labs/keymint`.
