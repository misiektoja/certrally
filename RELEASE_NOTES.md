# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.1.0 - TBD

The first version requests and revokes certificates over CMP, asks the CA for its certificates, request template and CRLs, checks that a server answers and generates keys, including ML-DSA and composite ML-DSA keys. It also enrolls, renews and gets server-generated keys over EST, signing in with a password, a TLS client certificate or TLS-SRP. On a terminal, enroll can ask for each setting step by step. Built-in CMP and EST test CAs let you try it without a real CA. Each exchange is shown as a live message diagram. certrally warns about responses that break RFC 9483 or RFC 7030. A strict profile rejects them. Scripts get the outcome as JSON. Every message of a run can be recorded to a file, decoded later and checked against those rules. Releases come as archives for Linux, macOS and Windows, a Homebrew cask and a container image.

### Enrollment

* **`certrally enroll`** requests a certificate with an initialization (`ir`), certification (`cr`), key update (`kur`) or PKCS#10 (`p10cr`) request. It polls while the CA prepares the certificate, confirms it and saves it with `--cert-out`, the new key with `--key-out` and the issuing CA certificates with `--chain-out`.
* **Shared-secret protection** uses `--ref` and a secret from `--secret-file`, the `CERTRALLY_SECRET` environment variable or a prompt. The secret is never taken from the command line. PBMAC1 is the default and `--mac pbm` selects PasswordBasedMac for CAs that accept only that. **Signature protection** uses `--cert` and `--key`.
* **No trust setup** is needed. certrally trusts the CA certificates in the first response and in the `--cert` file. **`--ca-cert`** names the CA to expect instead. Then nothing the server sends is trusted by itself. `--tls-ca-cert` replaces the system roots for HTTPS. Over plain HTTP only `--ca-cert` authenticates the CA.
* **Key types** cover ECDSA P-256 (the default), P-384 and P-521, Ed25519, RSA 2048 to 4096, ML-DSA-44, ML-DSA-65 and ML-DSA-87 and the composite ML-DSA combinations. `--new-key` certifies an existing key and `--csr` sends an existing PKCS#10 request.
* **Step-by-step enrollment**: on a terminal, `certrally enroll` without flags asks for each setting and checks every answer. **`--interactive`** asks only for what the given flags leave out. Before sending, certrally prints the same request as one command and asks for confirmation. The shared secret is hidden and never printed. `ACCESSIBLE=1` asks line by line.
* `--subject` takes an RFC 4514 name and `--san` adds DNS names, IP addresses, email addresses and URIs. `--recipient`, `--sender` and `--cert-profile` set the matching request header fields.
* A **ladder diagram** on standard error shows every message with its protection, size, status and round-trip time. Failures are explained with the CA status, its failure reasons and a hint about which flag to check. `--quiet` hides the diagram and the summary.
* Private keys are saved as PKCS#8 PEM with mode 0600. Existing files are kept unless `--force` is given. certrally checks this before it sends a request.
* **Exit statuses** separate failures: 1 for an invalid command line or local error, 2 when the server is unreachable or does not answer with CMP or EST, 3 when the CA or EST server refuses the request, 4 for protocol or verification failures, 5 when the certificate was issued but the confirmation failed and 6 when a response breaks the strict profile.

### Revocation and CA information

* **`certrally revoke`** revokes the certificate in `--cert` with a request signed by its own key. An authority names the certificate with `--revoke-cert` instead. `--reason` takes the RFC 5280 reason names, including `certificateHold` and `removeFromCRL`. On a terminal it asks before sending unless `--yes` is given.
* **`certrally cacerts`** gets the CA certificates. **`certrally cmp genm`** sends the RFC 9483 support messages: `cacerts`, `rootupdate` for a replaced root CA certificate, `template` for the subject, extensions and key types the CA expects, `crl` and `crlupdate` for CRLs and `raw` for any info type. A received CRL is checked against the trusted CA certificates. `--out` saves certificates and CRLs. `--out -` writes them to standard output.

### EST

* **`certrally est`** talks to EST servers (RFC 7030) over HTTPS. **`est enroll`** requests a certificate, **`est reenroll`** renews the one in `--cert` with the same subject and subjectAltName and **`est serverkeygen`** gets a certificate with a key the server generates. **`est cacerts`** gets the CA certificates and **`est csrattrs`** shows what the CA wants in a request. `--server` may end in `/.well-known/est/LABEL` to choose a CA.
* **Sign-in** uses a password over HTTP Basic authentication with `--user`, a TLS client certificate with `--cert` and `--key` or **TLS-SRP** with `--srp`, which also authenticates the server without a certificate. The password comes from `--password-file`, the `CERTRALLY_PASSWORD` environment variable or a prompt. Renewal without `--key` signs in with the password, for certificates that cannot be used for TLS.
* **Trust**: the server certificate is checked against the system roots or `--tls-ca-cert`. **`est cacerts --bootstrap`** connects without the check and saves the certificates only after they match `--fingerprint` or a person confirms the fingerprint.
* When the server answers that a request is pending, certrally **waits as `Retry-After` asks** and sends it again, within `--timeout`. `--tls-unique` binds a request to the TLS 1.2 session. Server-generated keys are saved like other keys. Keys the server encrypts are not supported.
* **`certrally est mock`** runs an EST test CA on `127.0.0.1:8443`. It accepts a password and certificates it issued, serves TLS-SRP with `--srp-listen` and answers with `202 Accepted` first with `--retry-after`.

### Server check, keys and test CA

* **`certrally ping`** checks that a server answers CMP without any credentials and reports the CA name, protection and round-trip time. `--count` repeats the check. With `--ca-cert` the answer must also be signed by that CA.
* **`certrally keygen`** generates any supported key type without contacting a CA. `--pub-out` saves the public key and `--csr-out` a PKCS#10 request for `--subject` and `--san`. `--list` prints the key types.
* **`certrally mock`** runs a CMP test CA on your machine for trying certrally and testing scripts. It prints an `enroll` command that works against it and logs one line per request. It listens on `127.0.0.1:8080` and generates a shared secret unless `--listen`, `--ref` and `--secret-file` say otherwise. `--ca-out` saves its CA certificate for `--ca-cert`. It issues certificates for every key type certrally generates, including composite ML-DSA keys. Its key and certificates live in memory.

### Profiles

* **`--profile`** sets how certrally treats a response that breaks an RFC 9483 or RFC 9810 rule that some CAs do not follow, such as a missing certificate chain or a short nonce. For EST it covers RFC 7030 rules, such as an enrollment response that carries the CA chain or a `202 Accepted` without `Retry-After`. **`compatible`**, the default, accepts the response and prints a warning that names the rule. **`strict`** stops before accepting the response and exits with status 6. A rejection from the CA is still reported as a rejection. Some CAs copy the `senderKID` of a signed request into their responses. `compatible` warns and still checks the signature, chain and sender name, so signed enrollment and revocation work with such a CA. [docs/profiles.md](docs/profiles.md) lists the rules. [docs/interop.md](docs/interop.md) describes how EJBCA Community Edition and the OpenSSL CMP server behave.

### Scripts and records

* **`--json`** prints the outcome of `enroll`, `revoke`, `cacerts`, `cmp genm`, `ping`, `inspect`, `lint`, `keygen` and the `est` commands as one JSON document on standard output. It holds the exit status, every message of the exchange, the result of the command and any error. [docs/json.md](docs/json.md) describes the fields.
* **`--capture FILE`** appends every message of a run, with its bytes and timing, to a JSON Lines file. Several runs can share one file. New files get mode 0600, because the messages of a shared-secret exchange allow offline guessing of the secret.
* **`certrally inspect`** decodes CMP messages from capture files and from DER, base64, hex or PEM files. It shows the header, protection, body and extra certificates of each message. It checks signatures, also those of expired signer certificates or with a `senderKID` that names another key. With `--ca-cert` it also checks whether the signer chained to that CA when the capture recorded the message. It checks PBM and PBMAC1 MACs with the shared secret from `--secret-file` or `CERTRALLY_SECRET`. It also decodes EST captures and PKCS#10, PKCS#7 and CSR attribute files. **`certrally lint`** checks recorded responses against the profile rules and against the transaction ID and nonces of their requests. It exits with status 6 when a response breaks a rule. It checks EST responses in capture files.

### Installation

* **Release archives** for Linux, macOS and Windows on amd64 and arm64 come with a `checksums.txt` signed by cosign, an SPDX SBOM per archive and GitHub build provenance.
* **`brew install misiektoja/tap/certrally`** installs certrally and its shell completions on macOS and Linux.
* **`ghcr.io/misiektoja/certrally`** is a container image for linux/amd64 and linux/arm64. It runs as an unprivileged user.

### Command line

* **`certrally cmp`** runs the CMP commands, such as `certrally cmp enroll`. Without the prefix, `enroll`, `revoke`, `cacerts`, `ping` and `mock` use CMP.
* **`certrally --help`** describes the command and its flags. **`--version`** prints the version recorded at build time. **`certrally completion`** prints shell completion scripts for bash, zsh, fish and PowerShell. **`certrally man`** prints a man page.
* **`--color auto|always|never`** controls coloured output. `auto`, the default, colours output only on a terminal. `NO_COLOR` with any non-empty value turns colour off. `FORCE_COLOR` and `CLICOLOR_FORCE` turn it on for pipes and files. `--color` overrides all of them.
