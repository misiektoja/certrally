# Tested servers

certrally has been run against the CMP and EST servers below. Each section lists where the server differs from the RFCs or needs a particular setting, and what certrally shows in that case.

## CMP

### EJBCA Community Edition 9.6.3

Tested with a CMP alias in client mode that accepts the end entity password as the shared secret and end entity certificates for signed requests.

* `ir`, `cr`, `kur`, `p10cr` and `rr` work. `ir` was tested with ECDSA, RSA, Ed25519 and ML-DSA-65 keys. PBMAC1 and PasswordBasedMac both work.
* EJBCA signs its responses to MAC-protected requests, even with the alias response protection set to `pbe`. RFC 9483 section 3.2 asks for the same kind of protection in every message of an operation, so certrally warns and `--profile strict` stops the enrollment.
* `lint` found no other deviation in recorded `ir`, `p10cr`, `kur` and `rr` exchanges or in rejections.
* Error messages are unprotected. certrally shows the reason and marks the answer as not authenticated.
* General messages are rejected with `badRequest` "Can not handle message type '21'", so `cacerts` and `cmp genm` fail. `ping` still reports a CMP answer, but with `--ca-cert` it cannot check the unprotected answer and exits with status 4.
* In the tested setup EJBCA signed revocation responses with its ManagementCA instead of the CA that issued the certificate. With only the issuing CA in `--ca-cert`, `revoke` exits with status 4 although EJBCA has revoked the certificate. Put both CA certificates in `--ca-cert`.
* A `cr` signed with an end entity certificate is rejected with "Status NEW, FAILED or INPROCESS required" once the end entity has a certificate. Reset the end entity status in EJBCA first.
* Composite ML-DSA keys were rejected with "Illegal key algorithm, not authorized by certificate profile", even with the composite algorithms listed in the certificate profile.

### Nokia NCM 26.7

Tested over HTTP with a shared secret and with certificates that NCM issued.

* `ir`, `cr`, `p10cr`, `kur` and `rr` work, with and without `--ca-cert`. `ir` was tested with ECDSA P-256, P-384 and P-521 and RSA 2048 and 3072 keys.
* NCM accepts only PasswordBasedMac. It answers a PBMAC1-protected request with `badMessageCheck` "unsupported cmp header protection method". certrally then suggests `--mac pbm`.
* Ed25519, ML-DSA-65 and composite ML-DSA keys were rejected with `badPOP` "invalid PoP".
* NCM needs `--recipient` to choose the CA and answers `wrongAuthority` without it. It copies the recipient of the request into the sender of its responses. Give the CA name in the order certrally prints it, such as `--recipient 'CN=Issuing CA,O=Example,C=DE'`. With the names in another order, signed responses fail with "sender does not match protection certificate subject" and exit status 4.
* Responses to MAC-protected enrollment requests are MAC-protected, so `--profile strict` accepts them.
* Signed responses carry no senderKID, although the CA certificate has a subject key identifier. certrally warns about RFC 9483 section 3.1 and `--profile strict` stops a signed enrollment with exit status 6.
* Error messages are signed, so `ping --ca-cert` can check the answer.
* NCM answers every general message with the same `signKeyPairTypes`, `encKeyPairTypes` and `preferredSymmAlg` items instead of the requested one, so `cacerts` and `cmp genm` exit with status 3. The answer is signed even for a MAC-protected request and its extraCerts do not start with the signer certificate. certrally warns about RFC 9483 sections 3.2 and 3.3.
* With a rate limit configured, NCM answers requests that come too fast with HTTP 503 and no CMP message. certrally exits with status 2. Wait a few seconds between requests.

### Insta Certifier 10.0.0

Tested over HTTPS and HTTP with a shared secret and with certificates that Certifier issued.

* `ir`, `cr`, `p10cr`, `kur` and `rr` work. `ir` was tested with ECDSA P-256 and RSA 2048 keys.
* Certifier accepts only PasswordBasedMac. It answers a PBMAC1-protected request with an unprotected `notAuthorized` "authentication failed", so certrally cannot suggest `--mac pbm`.
* Signed responses copy the senderKID of the request instead of naming the key of the CA certificate. certrally warns about RFC 9483 section 3.1 and verifies the response with the CA certificate. `--profile strict` stops the enrollment with exit status 6.
* A `kup` carries no extraCerts. Without `--ca-cert` certrally cannot find its signer and exits with status 4 with a hint to pass the CA certificate. With `--ca-cert` the key update works and certrally warns about RFC 9483 section 3.3.
* Only certificates issued by `ir` authenticate a revocation request. An `rr` signed with a certificate that `cr` issued gets an unprotected `notAuthorized` "authentication failed".
* General messages are not supported. Each gets a signed error with `notAuthorized` "operation not supported", so `cacerts` and `cmp genm` exit with status 3.
* Unprotected requests get unprotected errors, so `ping --ca-cert` cannot check the answer and exits with status 4.

### OpenSSL 4.0.3 `openssl cmp` mock server

* The server accepts only PasswordBasedMac. It answers a PBMAC1-protected request with `badRequest` "no suitable sender cert", and certrally suggests `--mac pbm`.
* Its `kup` carries only the server certificate. Without `--ca-cert`, certrally cannot verify the new certificate and asks for the issuing CA certificate.
* The server process exits on `cmp genm template` and `cmp genm rootupdate` unless it is started with the options for them, `-ref_cert` and `-rsp_newwithnew`.

## EST

### Cisco libest 3.2.0 example server

Tested with the `estserver` example of libest 3.2.0 on OpenSSL 1.1.1, with a password, a client certificate and TLS-SRP.

* `est cacerts`, `est cacerts --bootstrap`, `est csrattrs`, `est enroll` and `est reenroll` work. `est cacerts` and `est enroll` also pass `--profile strict`.
* `est enroll` was tested with ECDSA P-256 and P-384, RSA 2048 and Ed25519 keys and with a PKCS#10 request from `--csr`. ML-DSA and composite ML-DSA requests get HTTP 400 "Invalid or corrupted pkcs10 request", because OpenSSL 1.1.1 does not support these algorithms.
* `est reenroll` works with the client certificate alone when the server runs with `-o`. Without `-o` the server also wants a password: a certificate alone gets HTTP 401 and certrally suggests `--user`. With `--cert`, `--key` and `--user` the renewal works.
* TLS-SRP works with `--srp` when the verifier uses a group of at least 2048 bits. The `passwd.srpv` that comes with libest holds `srpuser` with a 1536-bit group, which certrally refuses with "server chose the 1536 bit SRP group, below the minimum of 2048 bits".
* With `-t` the server requires the tls-unique binding. `--tls-unique` works. Without it the server answers HTTP 401 "Proof of Possession Mismatch".
* With `-h` the server asks for HTTP Digest authentication. certrally signs in with Basic only and gets HTTP 401.
* With `-m` the server answers `202 Accepted` with `Retry-After: 3600`. certrally exits with status 2 unless `--timeout` covers the hour.
* `est serverkeygen` exits with status 4. The server declares a `Content-Length` shorter than its multipart response, so the response ends before its last part. certrally also warns that the response has no `smime-type=certs-only` parameter, because the certificate part is cut off.
