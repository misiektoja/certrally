# Contributing

certrally is a certificate enrollment client for the Certificate Management Protocol (CMP). Bug reports, interoperability results and code contributions are welcome.

## Before contributing

Contribute only code you have the right to license under Apache-2.0. Do not copy code from another CMP implementation without checking its license and naming the source in the pull request.

Never commit shared secrets, private keys, full CSRs, CMP messages or packet captures from a production system, or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, test, lint and supply chain checks.

## Development checks

Run these before submitting a change:

```bash
make lint
make test
make build
```

`make test` runs `go vet` and the unit tests under the race detector. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. `make build` writes the binary to `bin/certrally`. Every recipe uses the Go toolchain named in `go.mod`.

Run `make actionlint` when a workflow changes, `make govulncheck` when a dependency changes and `make gitleaks` before pushing. `make help` lists every target.

User-facing behavior changes update the README and add an entry to [RELEASE_NOTES.md](RELEASE_NOTES.md). When the output of `enroll` or `revoke` changes, run `make demo` to record `docs/demo.gif` again. It needs [VHS](https://github.com/charmbracelet/vhs), ttyd and ffmpeg. Port 8080 must be free.

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Release notes

Release headings use `## vX.Y.Z - D Mon YYYY`, for example `## v0.1.0 - 2 Nov 2026`. Use an unpadded day and an abbreviated English month. Keep `TBD` until the release date is set.

## Releases

Pushing a `vX.Y.Z` tag on `main` starts the [release workflow](.github/workflows/release.yml). It checks that the tag is on the default branch, that RELEASE_NOTES.md has a dated section for the version and that the tests pass. GoReleaser then publishes the archives, the signed `checksums.txt`, the SBOMs, the container images on `ghcr.io/misiektoja/certrally` and the Homebrew cask. The release description is the RELEASE_NOTES.md section. Tags with a prerelease suffix are refused.

The workflow needs a repository secret named `HOMEBREW_TAP_TOKEN` that can push to `misiektoja/homebrew-tap`. GitHub creates the container package as private on the first release. Make it public in the package settings once.

`make release-snapshot` builds the archives, the cask and per-platform images into `dist/` without publishing. It needs Docker with Buildx. `SNAPSHOT_SKIP` lists the steps to leave out and defaults to `sign,sbom`, because signing needs the identity of a CI run and the SBOMs need syft. `make release-config-check` validates `.goreleaser.yaml`.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes, four spaces for shell scripts and two spaces for YAML and TOML. Markdown keeps meaningful trailing spaces. `LICENSE` stays verbatim.
