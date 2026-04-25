# keymint

Mint short-lived GitHub App installation tokens — for use as a CLI on
your laptop or as an in-cluster broker service.

## What it does

- **CLI mode**: reads a SOPS-encrypted GitHub App private key, signs a
  JWT, exchanges it for an installation access token, and prints the
  token to stdout. Pair with `git config credential.helper` to auth
  `git push` / `gh` invocations on private repos.
- **Service mode**: runs as an HTTP server inside Kubernetes. Validates
  inbound bearer tokens against the cluster's TokenReview API; if the
  caller's ServiceAccount is in the configured allowlist, mints an
  installation token and returns it.

The two modes share the same Go binary, the same config schema, and
the same JWT/HTTP signing logic — so you can adopt CLI-only for solo
dev and bolt on the service later (or vice versa) without rewriting
anything.

## Status

Early scaffold. Implementation lands in a sequence of small PRs:

| PR | Scope |
|----|-------|
| 1  | Repo scaffold (you are here) |
| 2  | `internal/mint` — JWT signing + `/access_tokens` |
| 3  | `internal/sops` + `internal/config` — config + SOPS decrypt |
| 4  | `internal/credhelper` — git credential helper protocol |
| 5  | `internal/server` — HTTP serve mode + TokenReview |
| 6  | Container image release wiring |
| 7  | Homebrew formula |

## Build

```sh
make build
```

Produces `build/keymint-$(GOOS)-$(GOARCH)` — static, CGO-disabled.

## Test

```sh
make test       # unit tests
make test-race  # with race detector + coverage
```

## Releasing

Releases are fully automated via release-please. Conventional commits
to `master` accumulate in a Release PR; merging that PR tags + cuts a
GitHub Release, which dispatches the container build to ghcr.io.

Never bump versions by hand.

## License

MIT — see [LICENSE](LICENSE).
