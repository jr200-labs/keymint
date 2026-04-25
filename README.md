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

## Contributing

This repo follows the jr200-labs convention:

- **`master` is protected** — direct pushes are blocked. Land changes via PR.
- **Squash-and-merge only** — merge commits and rebase merges are
  disabled. Each PR collapses to one commit on `master`. Branches are
  deleted automatically after merge.
- **Conventional Commits** — the squashed commit title becomes the PR
  title, so PR titles must follow the
  [Conventional Commits](https://www.conventionalcommits.org) spec
  (`feat: ...`, `fix(scope): ...`, etc.). CI runs `commitlint` on
  individual commits in the branch as well.
- **release-please** drives versioning. Never bump versions by hand;
  push conventional commits and let the Release PR open itself.

## Development setup

Install pre-commit hooks once after cloning. Hooks run `gofmt`, `go vet`,
`golangci-lint` (with the same shared config CI uses) on staged Go files
and `commitlint` on commit messages:

```sh
make hooks-install
```

Run hooks against every file in the repo:

```sh
make hooks-run
```

`pre-commit` itself comes from
[pre-commit.com](https://pre-commit.com); install via `brew install pre-commit`
or `uv tool install pre-commit`.

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

## Using as a git credential helper

Once `keymint mint <key>` works, you can wire it as a credential
helper so `git push` and `gh` calls against your configured orgs
authenticate automatically:

```sh
git config --global credential.https://github.com.helper "keymint helper"
git config --global credential.https://github.com.useHttpPath true
```

`useHttpPath = true` is required: by default git only sends `host` to
credential helpers, so every `github.com` remote looks identical and
keymint cannot tell which org's App should sign the token.

## Releasing

Releases are fully automated via release-please. Each PR merged to
`master` (squash, conventional commit) is picked up by release-please,
which keeps an open Release PR with the next version + changelog.
Merging that Release PR tags the version and cuts a GitHub Release,
which dispatches the container build to ghcr.io.

Never bump versions by hand.

## License

MIT — see [LICENSE](LICENSE).
