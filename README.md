# certrally

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/certrally?style=flat-square&color=blue)](https://github.com/misiektoja/certrally/releases)
[![GitHub Stars](https://img.shields.io/github/stars/misiektoja/certrally?style=flat-square&color=magenta)](https://github.com/misiektoja/certrally)
[![Last Commit](https://img.shields.io/github/last-commit/misiektoja/certrally?style=flat-square&color=green)](https://github.com/misiektoja/certrally/commits/main)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen?style=flat-square)](https://github.com/misiektoja/certrally)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/certrally/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/certrally/actions/workflows/test.yml)
[![Supply chain](https://github.com/misiektoja/certrally/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/certrally/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fcertrally&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/certrally)

certrally is a command line client for certificate enrollment with the Certificate Management Protocol (CMP), Enrollment over Secure Transport (EST) and the Simple Certificate Enrolment Protocol (SCEP).

![certrally enrolls an ML-DSA-65 certificate from the test CA with a shared secret](docs/demo.gif)

**CMP** (RFC 9810, which replaces RFC 4210, with the RFC 9483 profile)

* `ir`, `cr`, `kur`, `p10cr` and `rr` with a shared secret or a certificate
* Keys that the CA generates (central key generation)
* Requests forwarded by a registration authority in nested messages
* CA certificates, root CA updates, request templates and CRLs from the CA
* `ping` to check a server and `mock` to run a test CA on your machine
* Deliberately wrong messages with `enroll --fault` to test how a CA copes
* A step-by-step `enroll` that prints the matching command for scripts

**EST** (RFC 7030)

* Enrollment, renewal, server key generation, CA certificates and CSR attributes
* Authentication with a password, a bearer token, a TLS client certificate or TLS-SRP
* `est mock` to run a test EST CA on your machine

**SCEP** (RFC 8894)

* Enrollment, renewal and polling of pending requests, also in a later run
* CA certificates, the CA chain, the next CA certificate, certificates and CRLs from the CA
* Digest, cipher and HTTP method chosen from the server capabilities, with old algorithms on request
* `scep mock` to run a test SCEP CA on your machine

**All protocols**

* A live diagram of every message and plain explanations of failures
* RSA, ECDSA, Ed25519, ML-DSA, composite ML-DSA and ML-KEM keys, also offline with `keygen`. SCEP takes RSA and ECDSA keys
* No trust setup: certrally trusts the CA it talks to or the one in `--ca-cert`
* Warnings about responses that break the RFCs and a strict profile that rejects them
* JSON output, capture files and exit statuses for scripts
* `inspect` and `lint` to decode recorded messages and check them

Tested with EJBCA, Nokia NCM, Insta Certifier and the `openssl cmp` mock server over CMP, with Cisco libest over EST and with EJBCA, Nokia NCM, OpenXPKI and micromdm/scep over SCEP. See [docs/interop.md](docs/interop.md).

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

From source with Go 1.27.3 or newer:

```bash
go install github.com/misiektoja/certrally/cmd/certrally@latest
```

Releases are signed with cosign and carry GitHub build provenance and SBOMs. [docs/verify.md](docs/verify.md) shows how to check a download.

## Usage

```bash
certrally --help
certrally enroll --help
certrally --version
```

`certrally completion bash|zsh|fish|powershell` prints a shell completion script. `certrally man` prints a man page.

The CMP commands also run under `certrally cmp`, such as `certrally cmp enroll`. Without the prefix, `enroll`, `poll`, `revoke`, `cacerts`, `ping` and `mock` use CMP. The EST commands run under [`certrally est`](#enroll-over-est) and the SCEP commands under [`certrally scep`](#enroll-over-scep).

Output is coloured only on a terminal. [docs/output.md](docs/output.md) describes `--color`, `NO_COLOR`, `FORCE_COLOR` and the handling of existing output files.

### Try it with a test CA

`certrally mock` runs a CMP test CA on your machine and prints an `enroll` command that works against it:

```bash
certrally mock --ca-out ca.pem
```

Run the printed command in another terminal. Running `certrally enroll` without flags there asks for the settings instead. The test CA keeps everything in memory, so every run starts empty. Its fault flags make it delay, reject or relax its checks, to test how a client copes. [docs/mock.md](docs/mock.md) describes them.

### Enroll a certificate

A device that has a shared secret from its CA requests its first certificate with an initialization request (`ir`). `--ref` names the secret to the CA:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt \
  --subject CN=device-42,O=Example --san device-42.example.com \
  --cert-out device.pem --key-out device.key
```

`--secret VALUE` gives the secret on the command line instead, and `CERTRALLY_SECRET` or a prompt also work. [docs/cmp.md](docs/cmp.md#protection) lists the order and the risk of `--secret`.

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

`--type cr` requests an additional certificate. `--type p10cr` sends a PKCS#10 request, either from `--csr` or built from `--subject` and `--san`. Some CAs accept only PasswordBasedMac and need `--mac pbm`.

[docs/cmp.md](docs/cmp.md) covers the other options: key usages and templates, implicit confirmation, collecting a waiting certificate later, ML-KEM keys, keys that the CA generates, forwarding as a registration authority, CA information requests and `ping`. [docs/keys.md](docs/keys.md) covers key types, encrypted keys and DER output.

### Enroll step by step

On a terminal, `certrally enroll` without flags asks for each setting: the server, the CA to trust, the shared secret or certificate, the names, the key type and the files to write. Flags you give answer their questions. `--interactive` asks only for the rest:

```bash
certrally enroll --interactive --server https://ca.example.com/.well-known/cmp
```

Before it sends the request, certrally prints the same request as one command for scripts and asks for confirmation. The shared secret is hidden while you type it. It never appears in that command, and neither do the values of `--secret` and `--key-password`. The questions cannot be combined with `--json`. With `ACCESSIBLE=1` they are asked line by line, for example for a screen reader.

### Revoke a certificate

RFC 9483 signs a revocation request with the certificate being revoked:

```bash
certrally revoke --server https://ca.example.com/.well-known/cmp \
  --cert device.pem --key device.key --reason keyCompromise
```

`--reason` takes an RFC 5280 reason name and defaults to `unspecified`. `certificateHold` suspends a certificate and `removeFromCRL` releases it, if the CA supports holds. An authority that revokes for someone else names the certificate with `--revoke-cert` or with `--serial` and `--issuer` as described in [docs/cmp.md](docs/cmp.md#revoke-by-serial-number). On a terminal certrally asks before it sends the request. `--yes` skips the question.

### Trust the CA

certrally needs no trust setup. It trusts the CA certificates in the first response from the server and lists them with their SHA-256 fingerprints, so you can compare them with the ones the CA published. To make sure you talk to a particular CA, name its certificate with `--ca-cert ca.pem`. certrally then trusts nothing the server sends.

Over HTTPS the server is checked against the system roots or `--tls-ca-cert`. Over plain HTTP nothing authenticates the first response, so use `--ca-cert` there unless you trust the network. [docs/cmp.md](docs/cmp.md#trust-and-connections) covers `--chain-out`, `--insecure` and proxies.

### Enroll over EST

The `certrally est` commands talk to an EST server over HTTPS. `--server` is the address of the server, such as `https://est.example.com`. Add `/.well-known/est/LABEL` to choose a CA on a server that offers several.

| Command | What it does |
|---|---|
| `est cacerts` | Gets the CA certificates. `--out` saves them |
| `est csrattrs` | Shows the attributes, extensions and key types the CA wants in a request |
| `est enroll` | Requests a certificate for a new key, `--new-key` or `--csr` |
| `est reenroll` | Renews the certificate in `--cert`, with the same subject and subjectAltName |
| `est serverkeygen` | Requests a certificate and a key that the server generates |
| `est mock` | Runs an EST test CA on your machine |

```bash
certrally est enroll --server https://est.example.com --tls-ca-cert ca.pem \
  --user device-42 --password-file password.txt \
  --subject CN=device-42 --san device-42.example.com \
  --cert-out device.pem --key-out device.key
```

A client signs in with a password (`--user`), a bearer token (`--token`), a TLS client certificate (`--cert` and `--key`) or TLS-SRP (`--srp`). `est cacerts --bootstrap` gets the first CA certificates from a server that nothing can check yet and saves them after a fingerprint check. [docs/est.md](docs/est.md) describes the sign-in options, the bootstrap, proxies, waiting for the CA and the `est mock` test CA.

### Enroll over SCEP

The `certrally scep` commands talk to a SCEP server, usually over plain HTTP. `--server` is the SCEP URL of the server, such as `http://scep.example.com/scep`. A server with several CAs needs the name of the CA in `--ca`.

| Command | What it does |
|---|---|
| `scep caps` | Lists the capabilities of the server and the algorithms certrally picks from them |
| `scep cacert` | Gets the CA and RA certificates. `--fingerprint` and `--out` save them |
| `scep chain` | Gets the CA certificate and the certificates that issued it |
| `scep nextca` | Gets the CA certificate that will replace the current one |
| `scep enroll` | Requests a certificate for a new key, `--new-key` or `--csr` |
| `scep renew` | Renews the certificate in `--cert` |
| `scep poll` | Collects a certificate that the CA kept pending |
| `scep getcert`, `scep getcrl` | Get a certificate by its serial number or the CRL that covers a certificate |
| `scep mock` | Runs a SCEP test CA on your machine |

```bash
certrally scep enroll --server http://scep.example.com/scep --ca 'Issuing CA' --ca-cert ca.pem \
  --challenge-file challenge.txt --subject CN=device-42 \
  --cert-out device.pem --key-out device.key
```

Over plain HTTP nothing authenticates the first GetCACert answer, so save the CA certificates once with `scep cacert --fingerprint` and pass them with `--ca-cert`. The challenge password comes from `--challenge`, `--challenge-file` or `CERTRALLY_CHALLENGE`. When the CA answers PENDING, certrally keeps polling and saves the request in a state file that `scep poll` continues. [docs/scep.md](docs/scep.md) describes trust, algorithms, pending requests, renewal, queries and the `scep mock` test CA.

### Check responses against the RFCs

certrally warns when a response breaks a rule of RFC 9483, RFC 9810, RFC 7030 or RFC 8894 that some CAs do not follow. `--profile strict` rejects such responses instead and exits with status 6. [docs/profiles.md](docs/profiles.md) lists the rules. [docs/interop.md](docs/interop.md) describes how tested CAs behave.

### Use certrally in scripts

`--json` prints the outcome as one JSON document on standard output instead of the diagram and the report. The document holds the exit status, every message of the exchange, the result of the command and any error:

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --json \
  | jq -r '.result.certificates[].subject'
```

`--capture run.jsonl` appends every message of the run, with its bytes, to a JSON Lines file that [`inspect` and `lint`](#inspect-recorded-messages) read. Keep capture files private, because the messages of a shared-secret exchange allow offline guessing of the secret.

[docs/json.md](docs/json.md) describes both formats.

### Inspect recorded messages

`inspect` decodes recorded CMP, EST and SCEP messages and checks their signatures and MACs. `lint` checks recorded responses against the [profile rules](docs/profiles.md) and exits with status 6 when a response breaks one:

```bash
certrally inspect run.jsonl --ca-cert ca.pem
certrally lint run.jsonl
```

Both also read CMP and EST messages saved as DER, base64, hex or PEM. SCEP messages come from capture files. [docs/inspect.md](docs/inspect.md) shows the output and how signatures are checked.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid command line or local error, such as an unreadable file |
| 2 | The server could not be reached, did not answer in time or did not answer with CMP, EST or SCEP |
| 3 | The CA rejected the request, or the EST or SCEP server refused it or the sign-in |
| 4 | The response broke the protocol or failed verification |
| 5 | The CA issued the certificate but the confirmation failed. certrally saves the certificate. Check with the CA before retrying, because a retry can issue a second certificate |
| 6 | A response broke a rule of `--profile strict`, or `lint` found a response that breaks a rule |

## Documentation

* [CMP details](docs/cmp.md): request options, collecting a certificate later, ML-KEM keys, keys that the CA generates, registration authorities, trust, revocation by serial number, CA information and `ping`
* [EST details](docs/est.md): sign-in options, bootstrap, proxies, waiting, channel binding and the `est mock` test CA
* [SCEP details](docs/scep.md): trust, the challenge password, algorithms, pending requests, renewal, queries and the `scep mock` test CA
* [Keys and output files](docs/keys.md): key types, encrypted keys, `keygen` and DER output
* [The CMP test CA](docs/mock.md): `certrally mock` and its fault flags
* [Testing a CA with faulty messages](docs/faults.md): `enroll --fault` and `poll --fault`
* [Response profiles](docs/profiles.md): the rules certrally checks
* [JSON output and capture files](docs/json.md)
* [Inspect and lint recorded messages](docs/inspect.md)
* [Output and colour](docs/output.md)
* [Tested servers](docs/interop.md)
* [Verify a download](docs/verify.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

## License

certrally is licensed under the [Apache License 2.0](LICENSE).
