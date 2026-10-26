# certrally

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/certrally?style=flat-square&color=blue)](https://github.com/misiektoja/certrally/releases)
[![GitHub Stars](https://img.shields.io/github/stars/misiektoja/certrally?style=flat-square&color=magenta)](https://github.com/misiektoja/certrally)
[![Last Commit](https://img.shields.io/github/last-commit/misiektoja/certrally?style=flat-square&color=green)](https://github.com/misiektoja/certrally/commits/main)
[![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen?style=flat-square)](https://github.com/misiektoja/certrally)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/certrally/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/certrally/actions/workflows/test.yml)
[![Supply chain](https://github.com/misiektoja/certrally/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/certrally/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fcertrally&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/certrally)

certrally is a command line client for certificate enrollment with the Certificate Management Protocol (CMP) and Enrollment over Secure Transport (EST).

![certrally enrolls an ML-DSA-65 certificate from the test CA and revokes it](docs/demo.gif)

**CMP** (RFC 9810, which replaces RFC 4210, with the RFC 9483 profile)

* `ir`, `cr`, `kur`, `p10cr` and `rr` with a shared secret or a certificate
* CA certificates, root CA updates, request templates and CRLs from the CA
* `ping` to check a server and `mock` to run a test CA on your machine

**EST** (RFC 7030)

* Enrollment, renewal, server key generation, CA certificates and CSR attributes
* Authentication with a password, a TLS client certificate or TLS-SRP
* `est mock` to run a test EST CA on your machine

**Both protocols**

* A live diagram of every message and plain explanations of failures
* A step-by-step `enroll` that prints the matching command for scripts
* RSA, ECDSA, Ed25519, ML-DSA and composite ML-DSA keys, also offline with `keygen`
* No trust setup: certrally trusts the CA it talks to or the one in `--ca-cert`
* Warnings about responses that break the RFCs and a strict profile that rejects them
* JSON output, capture files and exit statuses for scripts
* `inspect` and `lint` to decode recorded messages and check them

Tested with EJBCA, Nokia NCM, Insta Certifier and the `openssl cmp` mock server over CMP and with Cisco libest over EST. See [docs/interop.md](docs/interop.md).

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

The CMP commands also run under `certrally cmp`, such as `certrally cmp enroll`. Without the prefix, `enroll`, `poll`, `revoke`, `cacerts`, `ping` and `mock` use CMP. The EST commands run under [`certrally est`](#enroll-over-est).

Output is coloured only on a terminal. [docs/output.md](docs/output.md) describes `--color`, `NO_COLOR` and `FORCE_COLOR`.

### Try it with a test CA

`certrally mock` runs a CMP test CA on your machine and prints an `enroll` command that works against it:

```bash
certrally mock --ca-out ca.pem
```

Run the printed command in another terminal. Running `certrally enroll` without flags there asks for the settings instead. The test CA keeps everything in memory, so every run starts empty. `certrally mock --help` lists its address and secret options. Fault flags such as `--waiting 2`, `--reject badCertTemplate` or `--accept sha1` make it delay, reject or relax its checks, to test how a client copes. [docs/mock.md](docs/mock.md) describes them.

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

* With a shared secret, the request header names `CN=<ref>` as the sender and `<ref>` as the key identifier, as RFC 9483 asks. Without `--subject` or `--san` the certificate is requested for `CN=<ref>`.
* Requests use CMP version 2, the syntax of RFC 4210, so servers built for RFC 4210 understand them. Only messages that need a field added by RFC 9810 use version 3, such as the confirmation of a certificate that the CA signed with ML-DSA or composite ML-DSA.
* Shared-secret requests are protected with PBMAC1. `--mac pbm` selects PasswordBasedMac for CAs that accept only that, such as Nokia NCM, Insta Certifier and the `openssl cmp` mock server. `--iterations` sets the MAC iteration count (default 10000).
* `--hash sha1|sha256|sha384|sha512` selects the digest of the signatures certrally makes with an RSA or ECDSA key: the message protection with `--cert`, the proof of possession and a PKCS#10 request. With `--mac pbm` it also selects the one-way function and HMAC of the MAC. PBMAC1 always uses SHA-256. The default follows the key type. CAs refuse SHA-1 unless configured to accept it.
* `--general-info OID:int:N`, `OID:str:TEXT` or `OID:hex:DER` (repeatable) adds an item to the generalInfo field of the request header, for example a vendor profile identifier that a CA keys its policy on. `--cert-req-id N` sets the certReqId of an `ir`, `cr` or `kur` (default 0), which the CA must repeat. RFC 9483 requires 0, so most CAs refuse other values.
* `--key-usage` and `--ext-key-usage` ask for the keyUsage and extendedKeyUsage extensions, as comma-separated lists such as `--key-usage digitalSignature,keyEncipherment --ext-key-usage serverAuth,clientAuth`. `--key-usage` takes `digitalSignature`, `nonRepudiation` (or `contentCommitment`), `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly` and `decipherOnly`. `--ext-key-usage` takes `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`, `anyExtendedKeyUsage` or a dotted OID. Names are not case-sensitive. keyUsage is marked critical, as RFC 5280 recommends. The CA decides what the certificate gets, and many CAs take the key usages from their profile instead.
* `--template-cert device.pem` copies the subject, subjectAltName, keyUsage and extendedKeyUsage of an existing certificate, to request one shaped like a certificate the CA already issued. `--subject`, `--san`, `--key-usage` and `--ext-key-usage` replace the part they set. A `kur` already repeats the certificate in `--cert`, so it does not take `--template-cert`. A `p10cr` built by certrally carries these extensions in its PKCS#10 request. A request given with `--csr` cannot be changed.
* `--implicit-confirm` asks the CA for implicit confirmation, as RFC 9483 recommends. A CA that grants it repeats `implicitConfirm` in its response and certrally skips the `certConf` exchange, so the run ends with the response. A CA that wants the confirmation leaves it out and certrally confirms as usual. The result says which happened.
* `--hash`, `--iterations` and `--general-info` also apply to `revoke` and the `genm` commands.
* Private keys are written as unencrypted PKCS#8 PEM with mode 0600. `certrally keygen --list` prints the key types. `--out-format der` writes DER instead of PEM: the certificate as is, the key as PKCS#8 and `--chain-out` as PKCS#7.
* `--key` and `--new-key` also take an encrypted PKCS#8 key, as `openssl pkcs8 -topk8` writes it (PBES2 with PBKDF2 and AES). The password comes from `--key-password-file` (`-` reads standard input), the `CERTRALLY_KEY_PASSWORD` environment variable or a prompt on a terminal, in that order. A key encrypted the older way, with `Proc-Type` headers in the PEM file, is not supported. `openssl pkcs8 -topk8 -in old.key -out device.p8` converts one.

### Collect a certificate later

A CA that needs approval answers with status `waiting`. `enroll` then polls until the CA decides or `--timeout` ends, 5 minutes by default. With `--poll-later` it stops at that answer instead, saves the new key and records the transaction in the `--capture` file:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt --subject CN=device-42 \
  --cert-out device.pem --key-out device.key \
  --poll-later --capture device.jsonl
```

```text
✓ Request waiting for the CA
  Status          waiting
  Transaction ID  d503c4aad8beeb7b34b820adb1809771
  Saved           device.key
  Note            Collect the certificate with: certrally poll --transaction-id d503c4aad8beeb7b34b820adb1809771 --capture device.jsonl
```

`poll` collects the certificate later, also from another directory. It takes the server, the protection, the trusted CA certificates and the output files from the capture file and reads the shared secret again. A run that signed with an encrypted key takes `--key-password-file` the same way. It polls until the CA decides, confirms the certificate and saves it:

```bash
certrally poll --transaction-id d503c4aad8beeb7b34b820adb1809771 \
  --capture device.jsonl --secret-file secret.txt
```

A poll that ends at `--timeout` while the CA still waits records the new state, so the same command can run again. An `enroll` whose polling ends at `--timeout` records the transaction the same way when it has `--capture`. `--server`, `--cert-out`, `--chain-out` and `--out-format` replace the values from the capture file. Once the CA issues the certificate or rejects the request, the transaction ends and `poll` refuses it. After other failures, such as a wrong shared secret, the same command can run again.

### Trust the CA

certrally needs no trust setup. It trusts the CA certificates in the first response from the server and the CA certificates in the `--cert` file, then checks every response against them. If a response does not carry the CA certificate that issued the new certificate, pass that certificate with `--ca-cert`.

To make sure you talk to a particular CA, name its certificate with `--ca-cert ca.pem` (repeatable). certrally then trusts nothing the server sends. Signed responses and issued certificates must chain to a CA certificate from `--ca-cert` or `--cert`.

Over HTTPS the server is checked against the system roots or against the CA certificates in `--tls-ca-cert`. `--insecure` skips that check, for a test server with a self-signed certificate. certrally then warns that anyone who intercepts the connection can pose as the server, and the capture file records it. `--insecure` cannot be combined with `--tls-ca-cert`. Over plain HTTP nothing authenticates the first response, so use `--ca-cert` there unless you trust the network.

certrally connects through the proxy that the `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` environment variables name, like other HTTP clients. `--proxy http://proxy.example.com:3128` names a proxy on the command line instead, on every command that talks to a server. An `https` proxy works too, and credentials in the URL are sent to the proxy.

### Revoke a certificate

RFC 9483 signs a revocation request with the certificate being revoked:

```bash
certrally revoke --server https://ca.example.com/.well-known/cmp \
  --cert device.pem --key device.key --reason keyCompromise
```

`--reason` takes an RFC 5280 reason name and defaults to `unspecified`. `certificateHold` suspends a certificate and `removeFromCRL` releases it, if the CA supports holds. An authority that revokes for someone else names the certificate with `--revoke-cert` and signs with its own `--cert` or a shared secret. On a terminal certrally asks before it sends the request. `--yes` skips the question.

An authority that has no copy of the certificate names it with `--serial` and `--issuer`. `--serial` takes a decimal number, hex with `0x` or the colon-separated hex that certrally prints. `--invalidity-date` tells the CA when the key was compromised or the certificate became invalid, as RFC 3339 or `YYYY-MM-DD`, for the CRL entry:

```bash
certrally revoke --server https://ca.example.com/.well-known/cmp \
  --ref ra-1 --serial 0x1A2B --issuer 'CN=Example CA' --reason keyCompromise --invalidity-date 2026-10-01
```

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

`--out -` writes the certificates or the CRL to standard output and moves the summary to standard error. `--out-format der` writes DER, with several certificates as PKCS#7.

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

With `--ca-cert` the answer must also be signed by that CA. A CA that leaves its errors unprotected fails this check.

### Generate a key

`keygen` creates a key without contacting a CA, for example to send a PKCS#10 request through another channel:

```bash
certrally keygen --key-type ml-dsa-65 --out device.key \
  --csr-out device.csr --subject CN=device-42 --san device-42.example.com
```

`--pub-out` also saves the public key. The key is saved like enroll keys, as unencrypted PKCS#8 PEM with mode 0600. `--out-format der` writes the key, the public key and the request as DER.

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

A client signs in with one of these:

* **A password** over HTTP Basic authentication with `--user`. The password comes from `--password-file` (`-` reads standard input), the `CERTRALLY_PASSWORD` environment variable or a prompt on a terminal, in that order.
* **A TLS client certificate** with `--cert` and `--key`. `est reenroll --cert device.pem --key device.key` renews a certificate this way. Without `--key`, renewal signs in with `--user` instead, as RFC 7030 section 2.3 allows for certificates that cannot be used for TLS. An encrypted `--key` or `--new-key` takes its password from `--key-password-file`, `CERTRALLY_KEY_PASSWORD` or a prompt, like for CMP.
* **TLS-SRP** with `--srp` and `--user`. The password then authenticates both sides over TLS 1.2, so the server needs no certificate and `--srp` cannot be combined with `--tls-ca-cert`.

`--out-format der` writes `--cert-out` and `--key-out` as DER and `est cacerts --out` as PKCS#7, like the CMP commands.

`--proxy` and the proxy environment variables work like for CMP. The EST commands tunnel through the proxy with CONNECT, so TLS-SRP and `--tls-unique` work through it.

The server certificate is checked against the system roots or against the CA certificates in `--tls-ca-cert`. `--insecure` skips that check, for a test server, and warns that anyone who intercepts the connection can pose as the server. When nothing can check the certificate yet, `est cacerts --bootstrap` connects without the check (RFC 7030 section 4.1.1). It saves the certificates only after the fingerprint matches `--fingerprint` or a person confirms it on a terminal:

```bash
certrally est cacerts --server https://est.example.com --bootstrap \
  --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --out ca.pem
```

[docs/est.md](docs/est.md) describes how certrally waits for a pending request, channel binding with `--tls-unique`, server-generated keys and the `est mock` test CA.

### Check responses against RFC 9483 and RFC 7030

certrally warns when a response breaks a rule of the Lightweight CMP Profile (RFC 9483) that some CAs do not follow, such as a missing chain for the new certificate. EST responses are checked against RFC 7030, for example for a chain where only the issued certificate belongs. `--profile strict` rejects such responses instead and exits with status 6. `lint` checks [recorded responses](#inspect-recorded-messages) the same way. [docs/profiles.md](docs/profiles.md) lists the rules. [docs/interop.md](docs/interop.md) describes how tested CAs behave.

### Use certrally in scripts

`--json` prints the outcome as one JSON document on standard output instead of the diagram and the report. The document holds the exit status, every message of the exchange, the result of the command and any error:

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --json \
  | jq -r '.result.certificates[].subject'
```

`--capture run.jsonl` appends every message of the run, with its bytes, to a JSON Lines file that [`inspect` and `lint`](#inspect-recorded-messages) read. Keep capture files private, because the messages of a shared-secret exchange allow offline guessing of the secret.

[docs/json.md](docs/json.md) describes both formats.

### Inspect recorded messages

`inspect` decodes recorded CMP and EST messages and checks their signatures and MACs. `lint` checks recorded responses against the [profile rules](docs/profiles.md) and exits with status 6 when a response breaks one:

```bash
certrally inspect run.jsonl --ca-cert ca.pem
certrally lint run.jsonl
```

Both also read messages saved as DER, base64, hex or PEM. [docs/inspect.md](docs/inspect.md) shows the output and how signatures are checked.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid command line or local error, such as an unreadable file |
| 2 | The server could not be reached, did not answer in time or did not answer with CMP or EST |
| 3 | The CA rejected the request, or the EST server refused it or the sign-in |
| 4 | The response broke the protocol or failed verification |
| 5 | The CA issued the certificate but the confirmation failed. certrally saves the certificate. Check with the CA before retrying, because a retry can issue a second certificate |
| 6 | A response broke a rule of `--profile strict`, or `lint` found a response that breaks a rule |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

## License

certrally is licensed under the [Apache License 2.0](LICENSE).
