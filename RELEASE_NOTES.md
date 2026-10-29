# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.4.0 - TBD

This release adds SCEP (RFC 8894) under `certrally scep`: enrollment, renewal, pending requests, CA certificates, queries and a SCEP test CA.

### SCEP

* **`scep enroll` and `scep renew`** request and renew certificates with PKCSReq and RenewalReq for RSA or ECDSA keys. The challenge password comes from `--challenge`, `--challenge-file` or `CERTRALLY_CHALLENGE` and a server with several CAs needs `--ca`. certrally picks the digest, cipher and HTTP method from the server capabilities. `--hash` and `--cipher` choose others, down to SHA-1, MD5 and DES for old CAs. **`--allow-des`** accepts answers that a server encrypts with single DES.
* **`scep poll`** collects a certificate that the CA keeps pending, for example until an operator approves it. `scep enroll` and `scep renew` poll on their own within `--timeout` and save a request that is still pending in a state file for `scep poll`. `--poll-later` stops at the first PENDING answer.
* **`scep cacert`, `scep chain` and `scep nextca`** get the CA and RA certificates, the chain up to the root and the next CA certificate. `--fingerprint` checks a SHA-256 or SHA-1 fingerprint and `--out` saves the checked certificates for `--ca-cert`.
* **`scep caps`, `scep getcert` and `scep getcrl`** list the server capabilities and get a certificate by its serial number or a CRL.
* **CertReps sent with an HTTP error status**, such as PENDING with 202 or FAILURE with 400, are read like any other answer. When a server refuses an enrollment with an HTTP error, certrally shows the text of its error page without HTML markup and suggests checking the challenge password, `--subject` and `--ca`.
* **HTTP 503 answers are sent again** up to `--busy-retries` times, after `Retry-After` or `--busy-wait`. `--proxy` also takes a SOCKS5 proxy for SCEP.
* **`certrally scep mock`** runs a SCEP test CA on `127.0.0.1:8090`. Its flags add an RA certificate, a next CA certificate, pending requests, busy answers and the capabilities of an old CA.
* **SCEP answers are checked against RFC 8894**, such as a GetCACaps list with a NUL byte or a CertRep without senderNonce. `--json`, `--capture`, `inspect` and `lint` work with the SCEP commands. See [SCEP details](https://github.com/misiektoja/certrally/blob/v0.4.0/docs/scep.md).

## v0.3.0 - 27 Oct 2026

This release takes secrets on the command line and asks before it replaces existing output files. It fixes the fingerprint question of `est cacerts --bootstrap`.

### CMP and EST

* **`--secret`, `--password`, `--key-password` and `--token=TOKEN`** give the CMP shared secret, the EST password, the password of an encrypted key and the EST bearer token on the command line. Every command with the matching `-file` flag takes them, including `poll`, `inspect`, `mock` and `est mock`. Other users of the machine can see these values in the process list, so the files, environment variables and prompt remain available. A bare `--token` still selects the token sign-in, so a token needs the `=` form. The command that the `enroll` questions print never shows these values.
* **certrally asks before it replaces an existing output file** when it runs on a terminal. The default answer is no and the question comes before any request is sent. Without a terminal, and with `--json`, an existing file still stops the command unless `--force` is given.

### Bug fixes

* **`est cacerts --bootstrap` asks on a terminal which certificate has the published fingerprint.** Before, it did not recognise the terminal and always stopped with an error asking for `--fingerprint`.

## v0.2.0 - 27 Oct 2026

This release adds ML-KEM keys, keys that the CA generates, forwarding as a registration authority, collecting a waiting certificate in a later run and revocation by serial number. It also adds tools to test CAs, encrypted key files, DER output, proxies and EST bearer tokens. It fixes what `est cacerts --bootstrap` and `--chain-out` save.

### CMP

* **ML-KEM-768 and ML-KEM-1024 keys.** `keygen` and `enroll --key-type` create them. `enroll` proves possession by decryption with **`--pop encrypted-cert`** (default) or **`--pop challenge`**.
* **`enroll --central-keygen`** asks the CA to generate the key pair (RFC 9483 section 4.1.6). certrally checks the signature of the key generation authority before it saves the key.
* **`enroll --ra-cert` and `--ra-key`** forward requests as a registration authority in signed `nested` messages (RFC 9483 section 5.2.2.1).
* **`enroll --poll-later` and `certrally poll`** collect a certificate that the CA keeps waiting, for example for an approval, in a later run. The `--capture` file holds the transaction.
* **`enroll --implicit-confirm`** asks the CA to skip the `certConf` exchange.
* **`enroll --key-usage`, `--ext-key-usage` and `--template-cert`** ask for key usages or copy the subject, subjectAltName and key usages of an existing certificate.
* **`revoke --serial` and `--issuer`** revoke a certificate without its file. **`--invalidity-date`** sets the invalidity date of the CRL entry.
* **`--cert-req-id`, `--general-info`, `--hash` and `--iterations`** set request fields and algorithms that some CA profiles need.
* **Trust on first response is reported.** Without `--ca-cert` the report lists each certificate trusted from the first response with its SHA-256 fingerprint. Over plain HTTP certrally also warns that nothing authenticated them.

### EST

* **`est --token` and `--token-file`** sign in with an HTTP bearer token (RFC 6750) instead of a password.

### CMP and EST

* **`--insecure`** skips the check of the TLS certificate of the server, for test servers. certrally warns and records the flag in the capture file.
* **Encrypted private keys.** `--key` and `--new-key` read encrypted PKCS#8 keys. The password comes from **`--key-password-file`**, `CERTRALLY_KEY_PASSWORD` or a prompt.
* **`--out-format der`** writes the output files as DER instead of PEM, with several certificates as PKCS#7.
* **`--proxy URL`** connects through an HTTP or HTTPS proxy. The EST commands now also follow `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`.
* **`certrally --help`** names the version of the build in its first line.

### Testing and troubleshooting

* **`enroll --fault` and `poll --fault`** send deliberately wrong messages, such as a `certConf` with a wrong certHash or a reused nonce, to test how a CA copes. See [faulty messages](https://github.com/misiektoja/certrally/blob/v0.2.0/docs/faults.md).
* **`certrally mock` fault flags** make the test CA keep requests waiting, reject them, grant implicit confirmation, enforce RFC 9483 strictly or accept deviations such as SHA-1. The test CA also refuses a late `certConf`, accepts registration authorities and logs revocations. Its rejections carry only the reason in the statusString, without the `server: status rejection` prefix. See [the CMP test CA](https://github.com/misiektoja/certrally/blob/v0.2.0/docs/mock.md).
* **`certrally est mock --token-file`** makes the EST test CA also accept a bearer token.

### Bug fixes

* **`est cacerts --bootstrap` saves only the checked certificate** and the certificates it issued. Before, every certificate of the response was saved once one matched, so the unchecked server could add a CA that `--tls-ca-cert` trusted later. It also refuses the sign-in flags, which sent the password or token to the unchecked server.
* **`--chain-out` holds only CA certificates that signed the new certificate.** Before, a certificate from the unprotected extraCerts entered the chain file when it copied the name and key identifier of the CA.
* **The RFC 9483 section 3.3 check verifies the protection certificate** with the signature of the response. Before, a certificate that copied the name and key identifier of the CA passed the check.

## v0.1.1 - 22 Oct 2026

This release fixes the Homebrew install.

### Bug fixes

* **`brew install misiektoja/tap/certrally` installs working shell completions** for bash, zsh, fish and PowerShell. With v0.1.0 macOS showed a "certrally Not Opened" dialog for each shell and no completions were installed. On Linux the completion files held the help text of `certrally completion`. Homebrew also no longer warns that the cask uses the deprecated `postflight` stanza.

## v0.1.0 - 22 Oct 2026

The first release of **certrally**, a command line client for certificate enrollment with CMP (RFC 9810, which replaces RFC 4210, with the RFC 9483 profile) and EST (RFC 7030). It shows every message of an exchange as a live diagram, explains failures in plain words and warns when a server breaks the protocol rules. Built-in test CAs let you try it without a real CA. Tested over CMP with EJBCA Community Edition 9.6.3, Nokia NCM 26.7, Insta Certifier 10.0.0 and the OpenSSL 4.0.3 mock server and over EST with the Cisco libest 3.2.0 example server, see [tested servers](https://github.com/misiektoja/certrally/blob/v0.1.0/docs/interop.md).

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
