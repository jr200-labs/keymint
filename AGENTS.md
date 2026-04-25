# keymint — agent notes

## What this is

Single Go binary that mints short-lived GitHub App installation tokens.
Two modes:

- **CLI** (`keymint mint <key>`, `keymint helper`) — laptop dev tool, reads
  SOPS-encrypted PEM on demand
- **Service** (`keymint serve`) — in-cluster HTTP broker, validates
  Kubernetes ServiceAccount tokens via TokenReview, mints for callers
  in the configured allowlist

## Project conventions

- **Language**: Go 1.26+
- **Module**: `github.com/jr200-labs/keymint`
- **Layout**: cmd/keymint + internal/{version,logging,mint,sops,config,server,credhelper}
- **CLI framework**: cobra root + per-subcommand `new<Name>Cmd()` constructors
- **Logging**: zap; `internal/logging.Setup(level, humanReadable)` at startup
- **Version**: `internal/version.Version` injected via ldflags from
  `.release-please-manifest.json` at build time
- **Build**: `make build` produces `build/keymint-$(GOOS)-$(GOARCH)`,
  static, CGO-disabled
- **Lint**: `make lint` downloads shared `.golangci.yml` from
  `jr200-labs/github-action-templates` (sync-shared pattern)
- **Tests**: unit tests next to code; integration tests under
  `tests/integration/` with `-tags=integration`

## Release flow

- release-please drives all releases
- Conventional commits required (`commitlint` enforced in CI)
- Squash-merge enforced at org level (jr200-labs)
- Merging the release-please PR cuts a tag + GitHub Release
- Release dispatches docker build → publishes
  `ghcr.io/jr200-labs/keymint:vX.Y.Z`

## What this repo does NOT contain

- Helm chart — consumers deploy via stakater/application or their own chart
- Project-specific config — entirely generic, no whengas/jr200-labs hardcoded
- Webhook server — token mint only

## Linked work

Built as part of the `Agent identity & merge gate` initiative at
https://linear.app/whengas/project/agent-identity-and-merge-gate-c8fb12319ebc.
The parent ticket is WG-105; this repo's scaffolding is WG-119.
