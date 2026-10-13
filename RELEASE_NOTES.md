# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.1.0 - TBD

The first version requests and revokes certificates over CMP, asks the CA for its certificates, request template and CRLs, checks that a server answers and generates keys, including ML-DSA and composite ML-DSA keys. Each exchange is shown as a live message diagram and needs no trust setup. certrally warns about responses that break RFC 9483. A strict profile rejects them. Scripts get the outcome as JSON. Every message of a run can be recorded to a file. Releases come as archives for Linux, macOS and Windows, a Homebrew cask and a container image.

### Enrollment

* **`certrally enroll`** requests a certificate with an initialization (`ir`), certification (`cr`), key update (`kur`) or PKCS#10 (`p10cr`) request. It polls while the CA prepares the certificate, confirms it and saves it with `--cert-out`, the new key with `--key-out` and the issuing CA certificates with `--chain-out`.
* **Shared-secret protection** uses `--ref` and a secret from `--secret-file`, the `CERTRALLY_SECRET` environment variable or a prompt. The secret is never taken from the command line. PBMAC1 is the default and `--mac pbm` selects PasswordBasedMac. **Signature protection** uses `--cert` and `--key`.
* **No trust setup** is needed. certrally trusts the CA certificates in the first response and in the `--cert` file. **`--ca-cert`** names the CA to expect instead. Then nothing the server sends is trusted by itself. `--tls-ca-cert` replaces the system roots for HTTPS. Over plain HTTP only `--ca-cert` authenticates the CA.
* **Key types** cover ECDSA P-256 (the default), P-384 and P-521, Ed25519, RSA 2048 to 4096, ML-DSA-44, ML-DSA-65 and ML-DSA-87 and the composite ML-DSA combinations. `--new-key` certifies an existing key and `--csr` sends an existing PKCS#10 request.
* `--subject` takes an RFC 4514 name and `--san` adds DNS names, IP addresses, email addresses and URIs. `--recipient`, `--sender` and `--cert-profile` set the matching request header fields.
* A **ladder diagram** on standard error shows every message with its protection, size, status and round-trip time. Failures are explained with the CA status, its failure reasons and a hint about which flag to check. `--quiet` hides the diagram and the summary.
* Private keys are saved as PKCS#8 PEM with mode 0600. Existing files are kept unless `--force` is given. certrally checks this before it sends a request.
* **Exit statuses** separate failures: 1 for an invalid command line or local error, 2 when the server is unreachable or does not answer with CMP, 3 when the CA rejects the request, 4 for protocol or verification failures, 5 when the certificate was issued but the confirmation failed and 6 when a response breaks the strict profile.

### Revocation and CA information

* **`certrally revoke`** revokes the certificate in `--cert` with a request signed by its own key. An authority names the certificate with `--revoke-cert` instead. `--reason` takes the RFC 5280 reason names, including `certificateHold` and `removeFromCRL`. On a terminal it asks before sending unless `--yes` is given.
* **`certrally cacerts`** gets the CA certificates. **`certrally cmp genm`** sends the RFC 9483 support messages: `cacerts`, `rootupdate` for a replaced root CA certificate, `template` for the subject, extensions and key types the CA expects, `crl` and `crlupdate` for CRLs and `raw` for any info type. A received CRL is checked against the trusted CA certificates. `--out` saves certificates and CRLs. `--out -` writes them to standard output.

### Server check and keys

* **`certrally ping`** checks that a server answers CMP without any credentials and reports the CA name, protection and round-trip time. `--count` repeats the check. With `--ca-cert` the answer must also be signed by that CA.
* **`certrally keygen`** generates any supported key type without contacting a CA. `--pub-out` saves the public key and `--csr-out` a PKCS#10 request for `--subject` and `--san`. `--list` prints the key types.

### Profiles

* **`--profile`** sets how certrally treats a response that breaks an RFC 9483 or RFC 9810 rule that some CAs do not follow, such as a missing certificate chain or a short nonce. **`compatible`**, the default, accepts the response and prints a warning that names the rule. **`strict`** stops before accepting the response and exits with status 6. A rejection from the CA is still reported as a rejection. [docs/profiles.md](docs/profiles.md) lists the rules.

### Scripts and records

* **`--json`** prints the outcome of `enroll`, `revoke`, `cacerts`, `cmp genm`, `ping` and `keygen` as one JSON document on standard output. It holds the exit status, every message of the exchange, the result of the command and any error. [docs/json.md](docs/json.md) describes the fields.
* **`--capture FILE`** appends every message of a run, with its bytes and timing, to a JSON Lines file. Several runs can share one file. New files get mode 0600, because the messages of a shared-secret exchange allow offline guessing of the secret.

### Installation

* **Release archives** for Linux, macOS and Windows on amd64 and arm64 come with a `checksums.txt` signed by cosign, an SPDX SBOM per archive and GitHub build provenance.
* **`brew install misiektoja/tap/certrally`** installs certrally and its shell completions on macOS and Linux.
* **`ghcr.io/misiektoja/certrally`** is a container image for linux/amd64 and linux/arm64. It runs as an unprivileged user.

### Command line

* **`certrally --help`** describes the command and its flags. **`--version`** prints the version recorded at build time. **`certrally completion`** prints shell completion scripts for bash, zsh, fish and PowerShell. **`certrally man`** prints a man page.
* **`--color auto|always|never`** controls coloured output. `auto`, the default, colours output only on a terminal. `NO_COLOR` with any non-empty value turns colour off. `FORCE_COLOR` and `CLICOLOR_FORCE` turn it on for pipes and files. `--color` overrides all of them.
