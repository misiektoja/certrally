# Tested servers

certrally has been run against the CMP, EST and SCEP servers below. Each section lists where the server differs from the RFCs or needs a particular setting. It also says what certrally shows in that case.

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

## SCEP

### EJBCA Community Edition 9.6.3

Tested over HTTP with the CA name in `--ca`. No end entity was registered for the requests, so no certificate was issued.

* EJBCA lists POSTPKIOperation, Renewal, SHA-512, SHA-256, SHA-1, DES3, AES and SCEPStandard. `scep caps`, `scep cacert` and `scep chain` work. GetCACert returns the issuing CA and its root. GetCACertChain returns the CA followed by its root. `lint` found no deviation.
* GetNextCACert gets `403 Forbidden` with an HTML page when the CA has no rollover certificate. `scep nextca` exits with status 3 and shows the text of the page.
* A PKCSReq without a challenge password gets `400 Bad Request` and one for a subject without an end entity gets `403 Forbidden`, each with an HTML page instead of a FAILURE answer. certrally exits with status 3, shows the text of the page and suggests checking the challenge password, `--subject` and `--ca`.

### Nokia NCM 26.7

Tested over HTTP with two NCM installations, with a SCEP CA that issues requests without operator approval and with one that waits for it.

* `scep caps`, `scep cacert`, `scep chain`, `scep nextca` and `scep enroll` work. `scep enroll` was tested with RSA 2048 and ECDSA P-256 keys, with the default SHA-256 and AES-128-CBC and with `--hash sha1 --cipher des3`.
* NCM needs `--ca`. Without it, GetCACert and GetCACertChain get HTTP 200 with an empty body. certrally then exits with status 2 and suggests `--ca`.
* NCM lists AES, SHA-1, SHA-256, SHA-512 and POSTPKIOperation and ends the list with a NUL byte. certrally warns about RFC 8894 section 3.5.2. `--profile strict` stops `scep caps` and every command that sends a PKIOperation, because they read the list first.
* `scep chain` returns the CA certificate followed by its root.
* GetNextCACert gets HTTP 200 with an empty body, which `scep nextca` reports as no next CA certificate.
* NCM signs its CertRep with SHA-1 whatever the request used, adds no senderNonce and no certificates. certrally verifies it with the certificate from GetCACert or `--ca-cert` and warns about RFC 8894 section 3.2.1.
* A CA that issues without approval also accepts a PKCSReq whose challenge password it does not know.
* A CA that waits for approval answers PENDING with HTTP 200. `scep enroll --poll-later` saved the request, `scep poll --once` got PENDING and `scep poll` collected the certificate after approval. `scep enroll` without `--poll-later` polled until the request was approved.
* RenewalReq, GetCert and GetCRL get HTTP 200 with an empty body. NCM does not list Renewal. certrally exits with status 2 and says that the server may not support the message type.

### OpenXPKI 3.34

Tested over HTTP with the `generic` SCEP endpoint of the OpenXPKI sample configuration. In this setup the server issued a certificate for a name in its test domain at once and kept a request for another name pending. Approval of a pending request was not tested.

* OpenXPKI lists Renewal, POSTPKIOperation, SHA-512, SHA-384, SHA-256, SHA-224, SHA-1, DES3 and AES. `scep caps`, `scep cacert`, `scep enroll` and `scep poll` work. `lint` found no deviation.
* GetCACert returns the RA certificate and the root CA but not the issuing CA, so `scep cacert` shows the root as the issuing CA.
* A pending request gets a PENDING CertRep with HTTP `202 Accepted`. certrally treats it as any PENDING answer and saves the state file. `scep poll --once` gets PENDING with HTTP 202 again.
* A PKCSReq with a wrong challenge password is kept pending as well, not refused, so `scep enroll` polls until `--timeout`.
* A RenewalReq gets a FAILURE CertRep with `badCertId` and HTTP `400 Bad Request`, although the server lists Renewal. certrally exits with status 3.
* GetCACertChain gets `400 Bad Request` "Unknown operation" and GetNextCACert gets `500 Internal Server Error`. `scep chain` and `scep nextca` exit with status 3.

### micromdm/scep 2.3.0

Tested with the `scepserver` of micromdm/scep 2.3.0 with a challenge password and `-allowrenew 0`.

* `scep caps`, `scep cacert`, `scep enroll` and `scep renew` work. `scep enroll` was tested with RSA 2048 and ECDSA P-256 keys, with the default SHA-256 and AES-128-CBC and with `--hash sha1 --cipher des3`. `lint` found no deviation.
* The server encrypts every CertRep with single DES, whatever the request used. Without `--allow-des` certrally exits with status 4 and suggests the flag.
* The server checks the challenge password in a RenewalReq as well, so `scep renew` needs `--challenge` or `--challenge-file`. Without it the renewal gets FAILURE with `badRequest`.
* GetCACertChain, GetNextCACert, GetCert and GetCRL get HTTP 500 "not implemented", so `scep chain`, `scep nextca`, `scep getcert` and `scep getcrl` exit with status 3.
