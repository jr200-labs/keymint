// Package version exposes the build-time version string for the
// keymint binary so it can be read by both the CLI (`version`
// subcommand) and the service runtime (logs, server identification).
//
// The default value "dev" is overwritten at build time via:
//
//	go build -ldflags "-X github.com/jr200-labs/keymint/internal/version.Version=v1.2.3"
//
// The Makefile's `build` target wires this from the VERSION read out of
// .release-please-manifest.json. CI builds inherit the same flag via
// the reusable workflow in jr200-labs/github-action-templates.
package version

// Version is the build-time injected version string. Defaults to "dev"
// for local `go run` / `go build` invocations that don't pass ldflags.
var Version = "dev"
