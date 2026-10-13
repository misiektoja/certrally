# certrally

certrally is a command line client for certificate enrollment with the Certificate Management Protocol (CMP, RFC 9810).

> [!NOTE]
> certrally is in early development and has not been released yet.

![certrally enrolls an ML-DSA-65 certificate from the test CA and revokes it](docs/demo.gif)

* Enrollment and key update over CMP (`ir`, `cr`, `kur`, `p10cr`) with a shared secret or a certificate
* A step-by-step `enroll` on a terminal that prints the matching command for scripts
* Revocation (`rr`) and the RFC 9483 support messages for CA certificates, root CA updates, request templates and CRLs
* `ping` to check that a server answers CMP and `keygen` to create keys and requests offline
* `mock` to run a CMP test CA on your machine, for trying certrally and testing scripts
* ML-DSA and composite ML-DSA keys alongside RSA, ECDSA and Ed25519
* No trust setup needed: certrally trusts the CA it talks to or the one you name with `--ca-cert`
* A live diagram of every message in the exchange and plain explanations of failures
* Warnings about responses that break RFC 9483 and a strict profile that rejects them
* JSON output for scripts and capture files that record every message of a run
* Exit statuses that tell scripts why a request failed

EST support is planned after CMP.

## Install

Each [release](https://github.com/misiektoja/certrally/releases) has archives for Linux, macOS and Windows on amd64 and arm64. A binary downloaded with a browser on macOS needs `xattr -d com.apple.quarantine certrally` before its first run, because it is not notarized.

With Homebrew on macOS or Linux, which also installs shell completions:

```bash
brew install misiektoja/tap/certrally
```

As a container image for linux/amd64 and linux/arm64:

```bash
docker run --rm ghcr.io/misiektoja/certrally --help
```

The image runs as an unprivileged user. To save files to the current directory, run it as your user and mount the directory:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work -e CERTRALLY_SECRET \
  ghcr.io/misiektoja/certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --cert-out device.pem --key-out device.key
```

From source with Go 1.27.2 or newer:

```bash
go install github.com/misiektoja/certrally/cmd/certrally@latest
```

### Verify a download

`checksums.txt` lists the SHA-256 digest of every archive. The release workflow signs it with a keyless cosign signature. Check the signature, then the archives:

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity https://github.com/misiektoja/certrally/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Archives and images also carry GitHub build provenance:

```bash
gh attestation verify certrally_0.1.0_linux_amd64.tar.gz --repo misiektoja/certrally
gh attestation verify oci://ghcr.io/misiektoja/certrally:0.1.0 --repo misiektoja/certrally
```

Each archive has an SPDX SBOM next to it, named after the archive with `.sbom.json` appended. The image carries its SBOM as an attestation.

## Usage

```bash
certrally --help
certrally enroll --help
certrally --version
```

`certrally completion bash|zsh|fish|powershell` prints a shell completion script. `certrally man` prints a man page.

### Try it with a test CA

`certrally mock` runs a CMP test CA on your machine and prints an `enroll` command that works against it:

```bash
certrally mock --ca-out ca.pem
```

Run the printed command in another terminal. Running `certrally enroll` without flags there asks for the settings instead. The test CA listens on `127.0.0.1:8080` unless `--listen` names another address. It generates a shared secret for the reference `demo` unless `--ref` and `--secret-file` or `CERTRALLY_SECRET` provide one. It logs one line per request and keeps its key and certificates in memory, so every run starts empty. It does not sign composite ML-DSA keys.

### Enroll a certificate

A device that has a shared secret from its CA requests its first certificate with an initialization request (`ir`). `--ref` names the secret to the CA:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt \
  --subject CN=device-42,O=Example --san device-42.example.com \
  --cert-out device.pem --key-out device.key
```

certrally draws each message as it is sent and received, then describes the certificate:

```text
  certrally                                           ca.example.com
  │                                                                │
  │ ir  PBMAC1  506 B                                              │
  │ ─────────────────────────────────────────────────────────────▶ │
  │                            ip  accepted  PBMAC1  1.5 KiB  9 ms │
  │ ◀───────────────────────────────────────────────────────────── │
  │ certConf  PBMAC1  291 B                                        │
  │ ─────────────────────────────────────────────────────────────▶ │
  │                                   pkiconf  PBMAC1  637 B  2 ms │
  │ ◀───────────────────────────────────────────────────────────── │

✓ Certificate issued
  Subject    CN=device-42,O=Example
  Alt names  device-42.example.com
  Issuer     CN=Example CA
  Serial     94:01:1D:E4:EA:C9:F1:25:59:06:0B:13:86:06:94:7D
  Valid      2026-10-13 00:20 UTC to 2027-10-13 00:21 UTC
  Key        ECDSA P-256
  Status     accepted
  Saved      device.key, device.pem
```

The diagram goes to standard error and the certificate summary to standard output. `--quiet` hides both.

A certificate the device already has signs later requests. A key update (`kur`) replaces the certificate in `--cert` with one for a new key:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp --type kur \
  --cert device.pem --key device.key \
  --cert-out device-new.pem --key-out device-new.key
```

`--type cr` requests an additional certificate. `--type p10cr` sends a PKCS#10 request, either from `--csr` or built from `--subject` and `--san`.

### Enroll step by step

On a terminal, `certrally enroll` without flags asks for each setting: the server, the CA to trust, the shared secret or certificate, the names, the key type and the files to write. It checks every answer before it moves on. Flags you give answer their questions. `--interactive` asks only for the rest:

```bash
certrally enroll --interactive --server https://ca.example.com/.well-known/cmp
```

Before it sends the request, certrally prints the same request as one command for scripts and asks for confirmation. The shared secret is hidden while you type it and never appears in that command. The questions need a terminal and cannot be combined with `--json`. With `ACCESSIBLE=1` they are asked line by line, for example for a screen reader.

Notes:

* The shared secret comes from `--secret-file` (`-` reads standard input), the `CERTRALLY_SECRET` environment variable or a prompt on a terminal, in that order. It is never accepted as a command line argument. One trailing line ending is removed.
* With a shared secret, the request header names `CN=<ref>` as the sender and `<ref>` as the key identifier, as RFC 9483 asks. Without `--subject` or `--san` the certificate is requested for `CN=<ref>`.
* Shared-secret requests are protected with PBMAC1. `--mac pbm` selects PasswordBasedMac for CAs that accept only that, such as the `openssl cmp` mock server.
* certrally generates an `ecdsa-p256` key unless `--key-type`, `--new-key` or `--csr` says otherwise. Key types are `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` and the composite ML-DSA combinations such as `mldsa65-ecdsa-p256-sha512`. Shell completion lists them all.
* Private keys are written as unencrypted PKCS#8 PEM with mode 0600. The key is written before the certificate. certrally refuses to replace an existing file unless `--force` is given. It checks this before sending anything.
* `--chain-out` saves the issuing CA certificates from the response, issuer first.
* `--timeout` (default 5 minutes) bounds the whole exchange, including polling while the CA prepares the certificate.

### Trust the CA

certrally needs no trust setup. It trusts the CA certificates in the first response from the server and the CA certificates in the `--cert` file, then checks every response against them. If a response does not carry the CA certificate that issued the new certificate, pass that certificate with `--ca-cert`.

To make sure you talk to a particular CA, name its certificate with `--ca-cert ca.pem` (repeatable). certrally then trusts nothing the server sends. Signed responses and issued certificates must chain to a CA certificate from `--ca-cert` or `--cert`.

Over HTTPS the server is checked against the system roots or against the CA certificates in `--tls-ca-cert`. Over plain HTTP nothing authenticates the first response, so use `--ca-cert` there unless you trust the network.

### Revoke a certificate

RFC 9483 signs a revocation request with the certificate being revoked:

```bash
certrally revoke --server https://ca.example.com/.well-known/cmp \
  --cert device.pem --key device.key --reason keyCompromise
```

`--reason` takes an RFC 5280 reason name and defaults to `unspecified`. `certificateHold` suspends a certificate and `removeFromCRL` releases it, if the CA supports holds. An authority that revokes for someone else names the certificate with `--revoke-cert` and signs with its own `--cert` or a shared secret. On a terminal certrally asks before it sends the request. `--yes` skips the question.

### Ask the CA for information

`cacerts` and the `cmp genm` commands send the RFC 9483 support messages. They are protected like enroll requests:

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --out ca-certs.pem
```

| Command | Answer |
|---|---|
| `cacerts` or `cmp genm cacerts` | The CA certificates. `--out` saves them |
| `cmp genm rootupdate --old-root root.pem` | The new root CA certificate, if the root has been replaced. It is accepted only when the old root certifies it |
| `cmp genm template` | The subject, extensions and key types the CA expects. `--cert-profile` selects a profile |
| `cmp genm crl` | The current CRL. Its signature is checked against the trusted CA certificates |
| `cmp genm crlupdate --crl ca.crl` | A CRL newer than `ca.crl`. `--crl-issuer ca.pem` asks for any CRL from that CA instead |
| `cmp genm raw caCerts` | The answer to any info types, given by name or as dotted OIDs |

`--out -` writes the certificates or the CRL to standard output and moves the summary to standard error.

### Check a server

`ping` sends an unprotected general message and reports who answers and how fast. It needs no credentials, because any CMP answer counts, including the error a CA sends back for an unprotected request:

```bash
certrally ping --server https://ca.example.com/.well-known/cmp --count 3
```

```text
  1  error rejection badMessageCheck  ECDSA SHA-256  690 B  12.4 ms
  2  error rejection badMessageCheck  ECDSA SHA-256  689 B  9.8 ms
  3  error rejection badMessageCheck  ECDSA SHA-256  688 B  10.1 ms
✓ The server answers CMP
  Server      https://ca.example.com/.well-known/cmp
  Answer      error rejection badMessageCheck
  CA says     "message not protected"
  Sender      CN=Example CA
  Protection  ECDSA SHA-256
  Round trip  min 9.8 ms, avg 10.8 ms, max 12.4 ms
  Replies     3 of 3
  Note        An error is the expected answer, because the request carries no protection.
```

With `--ca-cert` the answer must also be signed by that CA. `ping` exits with 0 when the server answers with CMP, 2 when it does not, 4 when the answer fails the `--ca-cert` check and 6 when it breaks `--profile strict`.

### Generate a key

`keygen` creates a key without contacting a CA, for example to send a PKCS#10 request through another channel:

```bash
certrally keygen --key-type ml-dsa-65 --out device.key \
  --csr-out device.csr --subject CN=device-42 --san device-42.example.com
```

`--pub-out` also saves the public key. `--list` prints the key types. The key is saved like enroll keys, as unencrypted PKCS#8 PEM with mode 0600.

### Check responses against RFC 9483

certrally warns when a response breaks a rule of the Lightweight CMP Profile (RFC 9483) that some CAs do not follow, such as a missing chain for the new certificate. `--profile strict` rejects such responses instead and exits with status 6. [docs/profiles.md](docs/profiles.md) lists the rules.

### Use certrally in scripts

`--json` prints the outcome as one JSON document on standard output instead of the diagram and the report. The document holds the exit status, every message of the exchange, the result of the command and any error:

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --json \
  | jq -r '.result.certificates[].subject'
```

`--capture run.jsonl` appends every message of the run, with its bytes, to a JSON Lines file for later inspection. Keep capture files private, because the messages of a shared-secret exchange allow offline guessing of the secret.

[docs/json.md](docs/json.md) describes both formats.

### Colour

certrally colours its output only when it writes to a terminal. These settings change that, highest priority first:

| Setting | Effect |
|---|---|
| `--color always` or `--color never` | Always or never use colour |
| `NO_COLOR` set to any non-empty value | No colour. Bold and other text styles remain on a terminal |
| `FORCE_COLOR` or `CLICOLOR_FORCE=1` | Colour even when the output is a pipe or a file. `FORCE_COLOR=0` and `FORCE_COLOR=false` have no effect |
| `TERM=dumb` | No colour |

The colour depth comes from `TERM` and `COLORTERM`.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid command line or local error, such as an unreadable file |
| 2 | The server could not be reached, did not answer in time or did not answer with CMP |
| 3 | The CA rejected the request |
| 4 | The response broke the protocol or failed verification |
| 5 | The CA issued the certificate but the confirmation failed. certrally saves the certificate. Check with the CA before retrying, because a retry can issue a second certificate |
| 6 | A response broke a rule of `--profile strict` |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

## License

certrally is licensed under the [Apache License 2.0](LICENSE).
