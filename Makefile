# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# GO_VERSION is the go directive in go.mod. Every recipe runs with exactly that toolchain, which is the
# one CI installs through go-version-file, so a newer local Go cannot change what the checks see.
# golangci-lint analyses the standard library of the toolchain in use, and a toolchain newer than the
# linter understands makes it crash rather than report a finding.
GO_VERSION := $(shell awk '$$1 == "go" && $$2 ~ /^[0-9]/ { print $$2; exit }' go.mod)
export GOTOOLCHAIN := go$(GO_VERSION)

.PHONY: all
all: test build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: | $(LOCALBIN) ## Build the certrally binary into bin/.
	CGO_ENABLED=0 go build -trimpath -o "$(LOCALBIN)/certrally" ./cmd/certrally

# DEMO_DIR receives the files that the demo recording writes, such as the test CA certificate.
DEMO_DIR ?= .cache/demo

.PHONY: demo
demo: build ## Record docs/demo.gif with VHS. Needs vhs, ttyd and ffmpeg.
	mkdir -p "$(DEMO_DIR)"
	PATH="$(LOCALBIN):$$PATH" DEMO_DIR="$(abspath $(DEMO_DIR))" vhs docs/demo.tape

.PHONY: fmt
fmt: ## Format the Go sources.
	go fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail when a tracked Go file is not gofmt formatted.
	@files=$$(git ls-files '*.go'); \
	if [ -z "$$files" ]; then echo "no Go files are tracked"; exit 1; fi; \
	unformatted=$$(gofmt -l $$files); \
	if [ -n "$$unformatted" ]; then echo "not gofmt formatted:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: tidy-check
tidy-check: ## Fail when go.mod or go.sum is not tidy.
	go mod tidy -diff

.PHONY: fix
fix: ## Modernize code to use newer Go APIs.
	go fix ./...

.PHONY: test
test: vet ## Run the unit tests under the race detector.
	go test -race -count=1 ./...

##@ Checks

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply the fixes it offers.
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify the golangci-lint configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: actionlint
actionlint: actionlint-tool ## Lint the GitHub Actions workflows.
	"$(ACTIONLINT)"

.PHONY: govulncheck
govulncheck: govulncheck-tool ## Report known vulnerabilities that reach the module or its dependencies.
	"$(GOVULNCHECK)" ./...

# GITLEAKS_LOG_OPTS selects the history the commit scan walks.
GITLEAKS_LOG_OPTS ?= --full-history --all
# Untracked directories that hold local state, tool binaries, build output and caches.
# .gitleaks.toml excludes them from the working tree scan.
GITLEAKS_EXCLUDED := local .cache bin dist

.PHONY: gitleaks
gitleaks: gitleaks-tool ## Scan the working tree and the commit history for leaked credentials.
# Excluded paths must not contain tracked files.
	@test -z "$$(git ls-files $(GITLEAKS_EXCLUDED))" || { echo "error: tracked files are excluded from the gitleaks scan by .gitleaks.toml"; exit 1; }
	"$(GITLEAKS)" dir . --config .gitleaks.toml --redact --no-banner
	"$(GITLEAKS)" git . --config .gitleaks.toml --redact --no-banner --log-opts="$(GITLEAKS_LOG_OPTS)"

# go-patch-check reaches go.dev, so it is not part of the other checks: govulncheck already fails on the
# consequence and an offline run should not fail for a reason unrelated to any vulnerability.
.PHONY: go-patch-check
go-patch-check: ## Report whether go.mod declares the newest Go patch in its release series.
	hack/go-patch-version.sh check

.PHONY: go-patch-update
go-patch-update: ## Move go.mod and the README build requirement to the newest Go patch in its series.
	hack/go-patch-version.sh update

# SBOM_VERSION names the SBOM after VERSION, or after the commit when no release is being made.
SBOM_VERSION = $(if $(VERSION),$(VERSION),$(shell git rev-parse --short HEAD))
SBOM_FILE = dist/certrally-$(SBOM_VERSION)-sbom.cdx.json

.PHONY: sbom
sbom: cyclonedx-gomod ## Generate a CycloneDX software bill of materials for the module. Set VERSION for a release.
	mkdir -p dist
	"$(CYCLONEDX_GOMOD)" mod -licenses -json -output "$(SBOM_FILE)" .
	@echo "Wrote $(SBOM_FILE)"

# SCAN_PLATFORM is the platform of the image scan-image builds and scans.
SCAN_PLATFORM ?= linux/amd64
SCAN_DIR ?= .cache/scan
# TRIVY_IMAGE runs the scanner as a container so no scanner binary has to be installed.
TRIVY_IMAGE ?= aquasec/trivy:0.74.0
# TRIVY_CACHE is the Docker volume that keeps the vulnerability database between runs.
TRIVY_CACHE ?= certrally-trivy-cache
TRIVY_SEVERITY ?= HIGH,CRITICAL

# scan-image builds the release image from the Dockerfile with a locally built binary, as GoReleaser
# does. The image reaches the scanner as an archive on standard input, so neither the container
# runtime socket nor a host directory has to be shared with the scanner.
.PHONY: scan-image
scan-image: ## Build the container image for SCAN_PLATFORM and scan it for known vulnerabilities.
	mkdir -p "$(SCAN_DIR)/$(SCAN_PLATFORM)"
	CGO_ENABLED=0 GOOS="$(word 1,$(subst /, ,$(SCAN_PLATFORM)))" GOARCH="$(word 2,$(subst /, ,$(SCAN_PLATFORM)))" go build -trimpath -o "$(SCAN_DIR)/$(SCAN_PLATFORM)/certrally" ./cmd/certrally
	docker build --platform "$(SCAN_PLATFORM)" --tag certrally:scan --file Dockerfile "$(SCAN_DIR)"
	docker save certrally:scan | docker run --rm -i -v "$(TRIVY_CACHE)":/root/.cache/trivy --entrypoint sh "$(TRIVY_IMAGE)" -c 'cat > /tmp/image.tar && trivy image --scanners vuln --severity "$(TRIVY_SEVERITY)" --ignore-unfixed --exit-code 1 --input /tmp/image.tar'

##@ Integration tests

# The integration tests run the binary that make build writes against real CMP and EST servers.
INTEGRATION_TEST = CERTRALLY_BIN="$(LOCALBIN)/certrally" go test -v -count=1 -tags integration
# EJBCA_HTTP_PORT is the host port of the EJBCA CMP endpoint.
EJBCA_HTTP_PORT ?= 8080
export EJBCA_HTTP_PORT
# LIBEST_IMAGE names the image of the libest example server that test-integration-libest builds.
LIBEST_IMAGE ?= certrally-libest
export LIBEST_IMAGE

.PHONY: test-integration
test-integration: test-integration-openssl test-integration-ejbca test-integration-libest ## Run every integration test. Needs OpenSSL 3.5 or newer and Docker.

.PHONY: test-integration-openssl
test-integration-openssl: build ## Run the CMP tests against the openssl cmp mock server. Needs OpenSSL 3.5 or newer on PATH.
	$(INTEGRATION_TEST) ./test/integration/openssl

.PHONY: setup-ejbca
setup-ejbca: ## Start EJBCA in Docker and configure it for the CMP tests.
	bash test/integration/ejbca/setup.sh

.PHONY: test-integration-ejbca
test-integration-ejbca: build setup-ejbca ## Run the CMP tests against EJBCA in Docker. EJBCA keeps running afterwards.
	$(INTEGRATION_TEST) ./test/integration/ejbca

.PHONY: teardown-ejbca
teardown-ejbca: ## Stop EJBCA and delete its container and data.
	docker compose -f test/integration/ejbca/docker-compose.yml down --volumes

.PHONY: test-integration-libest
test-integration-libest: build ## Build the Cisco libest example server image and run the EST tests against it.
	docker build -t "$(LIBEST_IMAGE)" test/integration/libest
	$(INTEGRATION_TEST) ./test/integration/libest

##@ Release

# VERSION names the release tag, for example v0.1.0.
VERSION ?=
# RELEASE_BODY receives the release notes of VERSION. It stays outside dist, which GoReleaser clears.
RELEASE_BODY ?= .cache/release-body.md
# SNAPSHOT_SKIP lists the GoReleaser steps a local snapshot leaves out. Signing needs the identity of
# a CI run and the SBOMs need syft.
SNAPSHOT_SKIP ?= sign,sbom

.PHONY: require-version
require-version:
	@test -n "$(VERSION)" || { echo "Set VERSION, for example VERSION=v0.1.0" >&2; exit 1; }

.PHONY: release-config-check
release-config-check: goreleaser ## Verify the GoReleaser configuration.
	"$(GORELEASER)" check

.PHONY: release-snapshot
release-snapshot: goreleaser ## Build the release archives and container images into dist/ without publishing.
	"$(GORELEASER)" release --snapshot --clean --skip="$(SNAPSHOT_SKIP)"

.PHONY: release-body
release-body: require-version ## Extract the RELEASE_NOTES.md section of VERSION into RELEASE_BODY.
	@if grep -q "^## $(VERSION) - TBD$$" RELEASE_NOTES.md; then echo "error: the RELEASE_NOTES.md section for $(VERSION) is dated TBD" >&2; exit 1; fi
	@mkdir -p "$(dir $(RELEASE_BODY))"
	@awk -v want="## $(VERSION) - " 'index($$0, want) == 1 { found = 1; next } found && /^## / { exit } found { print }' RELEASE_NOTES.md | sed '/./,$$!d' > "$(RELEASE_BODY)"
	@grep -q '[^[:space:]]' "$(RELEASE_BODY)" || { echo "error: RELEASE_NOTES.md has no section for $(VERSION)" >&2; exit 1; }
	@echo "Wrote $(RELEASE_BODY)"

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint
GOVULNCHECK ?= $(LOCALBIN)/govulncheck
GITLEAKS ?= $(LOCALBIN)/gitleaks
ACTIONLINT ?= $(LOCALBIN)/actionlint
GORELEASER ?= $(LOCALBIN)/goreleaser
CYCLONEDX_GOMOD ?= $(LOCALBIN)/cyclonedx-gomod

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION ?= v1.7.0
GITLEAKS_VERSION ?= v8.30.1
ACTIONLINT_VERSION ?= v1.7.12
# The release workflow installs the same GoReleaser version.
GORELEASER_VERSION ?= v2.18.3
CYCLONEDX_GOMOD_VERSION ?= v1.11.0

.PHONY: golangci-lint
golangci-lint: | $(LOCALBIN) ## Download golangci-lint locally if necessary.
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: govulncheck-tool
govulncheck-tool: | $(LOCALBIN) ## Download govulncheck locally if necessary.
	$(call go-install-tool,$(GOVULNCHECK),golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

.PHONY: gitleaks-tool
gitleaks-tool: | $(LOCALBIN) ## Download gitleaks locally if necessary.
	$(call go-install-tool,$(GITLEAKS),github.com/zricethezav/gitleaks/v8,$(GITLEAKS_VERSION))

.PHONY: actionlint-tool
actionlint-tool: | $(LOCALBIN) ## Download actionlint locally if necessary.
	$(call go-install-tool,$(ACTIONLINT),github.com/rhysd/actionlint/cmd/actionlint,$(ACTIONLINT_VERSION))

.PHONY: goreleaser
goreleaser: | $(LOCALBIN) ## Download GoReleaser locally if necessary.
	$(call go-install-tool,$(GORELEASER),github.com/goreleaser/goreleaser/v2,$(GORELEASER_VERSION))

.PHONY: cyclonedx-gomod
cyclonedx-gomod: | $(LOCALBIN) ## Download cyclonedx-gomod locally if necessary.
	$(call go-install-tool,$(CYCLONEDX_GOMOD),github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod,$(CYCLONEDX_GOMOD_VERSION))

# go-install-tool installs a package at a pinned version under a versioned directory and points the
# unversioned tool path at it, so a version bump installs the new tool instead of keeping the old one.
# $1 - tool path, $2 - package path, $3 - version
define go-install-tool
@dir="$(LOCALBIN)/.tools/$(notdir $(1))@$(3)"; \
if [ ! -x "$$dir/$(notdir $(1))" ]; then \
	echo "Downloading $(2)@$(3)"; \
	mkdir -p "$$dir"; \
	GOBIN="$$dir" go install "$(2)@$(3)"; \
fi; \
ln -sfn "$$dir/$(notdir $(1))" "$(1)"
endef
