# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.1.0 - 22 Oct 2026

The first release of **certrally**, a command line client for certificate enrollment with CMP (RFC 9810 and the RFC 9483 profile) and EST (RFC 7030). It shows every message of an exchange as a live diagram, explains failures in plain words and warns when a server breaks the protocol rules. Built-in test CAs let you try it without a real CA. Tested over CMP with EJBCA Community Edition 9.6.3, Nokia NCM 26.7, Insta Certifier 10.0.0 and the OpenSSL 4.0.3 mock server and over EST with the Cisco libest 3.2.0 example server, see [tested servers](https://github.com/misiektoja/certrally/blob/v0.1.0/docs/interop.md).

### CMP

* **`certrally enroll`** requests a certificate with `ir`, `cr`, `kur` or `p10cr`, protected with a shared secret or a signature. It needs no trust setup or checks the CA you name with `--ca-cert`. On a terminal it can ask for each setting step by step.
* **`certrally revoke`**, **`cacerts`** and **`cmp genm`** revoke certificates and get CA certificates, root CA updates, request templates and CRLs. **`certrally ping`** checks that a server answers CMP.

### EST

* **`certrally est`** enrolls, renews and gets server-generated keys, CA certificates and CSR attributes. It signs in with a password, a TLS client certificate or **TLS-SRP** and waits when the server asks it to retry later. `est cacerts --bootstrap` saves the first CA certificates after you confirm their fingerprint.

### Keys

* **ML-DSA and composite ML-DSA** keys work alongside ECDSA, Ed25519 and RSA. **`certrally keygen`** creates keys and PKCS#10 requests offline.

### Testing and troubleshooting

* **`certrally mock`** and **`certrally est mock`** run CMP and EST test CAs on your machine.
* **Profiles.** By default certrally warns when a response breaks a rule of RFC 9483, RFC 9810 or RFC 7030 that some CAs do not follow. `--profile strict` rejects such responses with exit status 6. See [profiles](https://github.com/misiektoja/certrally/blob/v0.1.0/docs/profiles.md).
* **`--capture`** records every message of a run. **`certrally inspect`** decodes captures and message files and checks their signatures and MACs. **`certrally lint`** checks recorded responses against the profile rules.
* **`--json`** prints the outcome as one JSON document, see [JSON output](https://github.com/misiektoja/certrally/blob/v0.1.0/docs/json.md). The exit status tells scripts why a request failed.

### Installation

* **Archives** for Linux, macOS and Windows on amd64 and arm64 come with a `checksums.txt` signed by cosign, SBOMs and build provenance, see [verify a download](https://github.com/misiektoja/certrally/blob/v0.1.0/docs/verify.md).
* **`brew install misiektoja/tap/certrally`** installs certrally and its shell completions on macOS and Linux.
* **`ghcr.io/misiektoja/certrally`** is a container image for linux/amd64 and linux/arm64.

### Known limitations

* **The macOS binaries are not notarized.** A binary downloaded with a browser needs `xattr -d com.apple.quarantine certrally` before its first run. The Homebrew cask removes the attribute.
* **`est serverkeygen`** cannot decrypt a key the server encrypts.
