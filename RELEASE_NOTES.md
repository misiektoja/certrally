# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.2.0 - TBD

This release adds ML-KEM keys, which prove possession by decryption, keys that the CA generates, requests forwarded by a registration authority, collecting a waiting certificate in a later run, implicit confirmation, revocation by serial number with an invalidity date, key usages and templates copied from an existing certificate, flags that shape a request the way a test scenario needs, fault flags that make the test CA delay, reject and relax its checks, deliberately wrong messages that test how a CA copes, `--insecure` for test servers with untrusted TLS certificates, encrypted private key files, DER output files, HTTP proxies and bearer tokens for EST.

### CMP and EST

* **`--insecure`** skips the check of the TLS certificate of the server on every command that talks to a server, for a test server with a self-signed certificate. certrally warns that anyone who intercepts the connection can pose as the server and records the flag in the capture file. It cannot be combined with `--tls-ca-cert`.
* **Encrypted private keys.** `--key` and `--new-key` take a PKCS#8 key encrypted the way `openssl pkcs8 -topk8` writes it, PBES2 with PBKDF2 and AES. The password comes from **`--key-password-file`** (`-` reads standard input), the `CERTRALLY_KEY_PASSWORD` environment variable or a prompt on a terminal. `poll` takes the same flag for the signing key of the enroll run. A key encrypted with `Proc-Type` PEM headers is still refused.
* **`--out-format der`** writes the output files as DER instead of PEM, on `enroll`, `poll`, `cacerts` and the `cmp genm` commands, `est enroll`, `est reenroll`, `est serverkeygen`, `est cacerts` and `keygen`. A certificate, a PKCS#8 key, a public key, a request and a CRL are written as is. A file that holds several certificates, such as `--chain-out` and the `--out` of the cacerts commands, becomes PKCS#7. `poll` keeps the format of the enroll run unless the flag replaces it. The default stays `pem`.
* **`--proxy URL`** connects through an http or https proxy, on every command that talks to a server. Without the flag, the `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` environment variables apply, which the EST commands ignored before. The EST commands tunnel through the proxy with CONNECT, so TLS-SRP and `--tls-unique` work through it.

### CMP

* **ML-KEM-768 and ML-KEM-1024 keys.** `keygen` and `enroll --key-type` create them and `--new-key` reads them, also in the forms OpenSSL writes. These keys cannot sign, so `enroll` proves possession by decryption with `ir`, `cr` and `kur`: with **`--pop encrypted-cert`**, the default, the CA encrypts the certificate for the key, and with **`--pop challenge`** certrally answers a challenge the CA encrypts. The CA must offer the method. `certrally mock --accept encrypted-cert-pop --accept challenge-pop` offers both. `poll` decrypts a waiting certificate with the saved key or `--new-key`. The result shows the method, as `proofOfPossession` in `--json`.
* **`enroll --central-keygen`** asks the CA to generate the key pair (RFC 9483 section 4.1.6) with `ir`, `cr` and `kur`. certrally checks the signature of the key generation authority, its certificate and that the key belongs to the certificate, then saves the key to `--key-out`. Without `--key-type` the CA chooses the key type. The CA encrypts the key to the shared secret or to an RSA or ECDSA `--key`. With `--poll-later`, `poll` saves the key with the certificate, to the file `enroll` named or to **`poll --key-out`**. The result names the authority, as `centralKeyGeneration` and `keyGenerationAuthority` in `--json`. `certrally mock` generates every key type that `--key-type` offers.
* **`enroll --ra-cert` and `--ra-key`** make certrally act as a registration authority (RFC 9483 section 5.2.2.1). It wraps every request, including the `certConf` and each `pollReq`, in a `nested` message signed with the RA certificate. The request inside keeps its own protection. The CA must accept the RA, usually by its cmcRA extended key usage, which **`--ext-key-usage cmcRA`** asks for. `poll` forwards through the same RA unless its own `--ra-cert` and `--ra-key` name another one. The result names the RA, as `registrationAuthority` in `--json`. The diagram shows the request inside, such as `nested(ir)`. Message records list it in `nested`. `certrally mock` accepts an RA whose certificate it issued with cmcRA. **`mock --require-ra`** refuses requests that no RA forwarded.
* **`revoke --serial` and `--issuer`** name the certificate to revoke without its file, for an authority that has only the serial number and the CA name. `--serial` takes a decimal number, hex with `0x` or the colon-separated hex that certrally prints. **`revoke --invalidity-date`** tells the CA when the key was compromised or the certificate became invalid, as RFC 3339 or `YYYY-MM-DD`, for the CRL entry. The `--json` result of `revoke` gains `issuer`, `serial` and `invalidityDate`.
* **`enroll --poll-later` and `certrally poll`** collect a certificate the CA keeps waiting, for example for an approval, in a later run. `enroll --poll-later` stops at the first `waiting` answer, saves the new key, prints the transaction ID and records the transaction in the `--capture` file. `poll --transaction-id ID --capture FILE` reads the server, protection, trusted CA certificates and output files from that file, polls until the CA decides, confirms the certificate and saves it. A poll or an `enroll` with `--capture` whose polling ends at `--timeout` records the transaction, so `poll` can continue it. The `--json` result of `enroll` and `poll` gains `transactionId`, and `nextPoll` for a waiting request.
* **`enroll --implicit-confirm`** asks the CA for implicit confirmation, as RFC 9483 recommends. When the CA grants it, certrally skips the `certConf` exchange and the result says so, in the text report and as `implicitConfirm` in `--json`. A CA that does not grant it gets the `certConf` as before.
* **`enroll --key-usage` and `--ext-key-usage`** ask for the keyUsage and extendedKeyUsage extensions as comma-separated names, such as `digitalSignature,keyEncipherment` and `serverAuth,clientAuth`. `--ext-key-usage` also takes a dotted OID. **`enroll --template-cert`** copies the subject, subjectAltName, keyUsage and extendedKeyUsage of an existing certificate, to request one shaped like a certificate the CA already issued. `--subject`, `--san`, `--key-usage` and `--ext-key-usage` replace the copied parts. `--template-cert` works with `ir`, `cr` and `p10cr`. The key usage flags also work with `kur`.
* **`enroll --cert-req-id`**, **`--general-info`**, **`--hash`** and **`--iterations`** set the certReqId, add generalInfo items such as a vendor profile identifier, select the digest of the signatures and of a PasswordBasedMac and set the MAC iteration count. `--hash`, `--iterations` and `--general-info` also apply to `revoke` and the `genm` commands.

### EST

* **`est --token` and `--token-file`** sign in with an HTTP bearer token (RFC 6750) instead of a password, on every `est` command. The token comes from `--token-file` (`-` reads standard input), the `CERTRALLY_TOKEN` environment variable or a prompt on a terminal, never from the command line. `--token` cannot be combined with `--user`. Renewal without a TLS client key still needs `--user`.

### Testing and troubleshooting

* **`certrally mock` fault flags** make the test CA answer with status `waiting` until a chosen poll (`--waiting`, `--check-after`), reject every request with a chosen failInfo (`--reject`), grant implicit confirmation (`--grant-implicit-confirm`), set the confirmation deadline (`--confirm-wait`), enforce RFC 9483 strictly (`--strict`), bound the MAC iteration count (`--mac-iterations`) and accept deviations from the profile on request (`--accept`, such as `sha1` or `any-cert-req-id`). The startup report shows the flags in use. [docs/mock.md](docs/mock.md) describes them.
* **`enroll --fault NAME`** and **`poll --fault NAME`** send a deliberately wrong message to test how a CA copes: a `certConf` that rejects the certificate (`reject-certificate`), names a wrong certHash or certReqId (`wrong-cert-hash`, `wrong-cert-req-id`), has no protection (`no-protection`) or arrives after the confirmWaitTime (`late-certconf`). Other faults make later messages reuse the senderNonce, carry a stale recipNonce or change the transactionID (`reuse-sender-nonce`, `stale-recip-nonce`, `wrong-transaction-id`). The flag is repeatable. `late-certconf` waits for **`--confirm-delay`** when the response sets no confirmWaitTime. The exit status follows the usual rules, certrally saves the certificate it received and the report names the faults sent, as `faults` in `--json`. `poll --fault` changes the pollReq and certConf of a transaction that the CA kept waiting. `enroll --fault` cannot be combined with `--poll-later`. [docs/faults.md](docs/faults.md) lists the RFC 9483 rule each fault breaks.
* **`certrally mock` refuses a late `certConf`** that arrives after the confirmWaitTime with badRequest. Its log shows the statusString of each response, such as the reason for a refusal. A request with a bad protection or recipient gets the reason alone in the statusString, such as `message not protected`. Before, the reason followed a `server: status rejection, failInfo: ...` prefix. `--strict` also refuses a pollReq or popdecr that repeats a senderNonce. It also notes a certificate that the client rejected or did not confirm in time.
* **`certrally mock` logs each revocation** with the serial number, the reason and the invalidity date the request gave, and lists the invalidity date in its CRL.
* **`certrally est mock --token-file`** or `CERTRALLY_TOKEN` makes the EST test CA also accept that bearer token. The startup report shows where the token comes from and prints the matching `est enroll --token` command.

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
