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

User-facing behavior changes update the README and add an entry to [RELEASE_NOTES.md](RELEASE_NOTES.md).

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Release notes

Release headings use `## vX.Y.Z - D Mon YYYY`, for example `## v0.1.0 - 2 Nov 2026`. Use an unpadded day and an abbreviated English month. Keep `TBD` until the release date is set.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes, four spaces for shell scripts and two spaces for YAML and TOML. Markdown keeps meaningful trailing spaces. `LICENSE` stays verbatim.
