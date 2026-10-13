# Tested CA servers

certrally has been run against the CMP servers below. Each section lists where the server differs from RFC 9483 or needs a particular setting, and what certrally shows in that case.

## EJBCA Community Edition 9.6.3

Tested with a CMP alias in client mode that accepts the end entity password as the shared secret and end entity certificates for signed requests.

* `ir`, `cr`, `kur`, `p10cr` and `rr` work. `ir` was tested with ECDSA, RSA, Ed25519 and ML-DSA-65 keys. PBMAC1 and PasswordBasedMac both work.
* EJBCA signs its responses to MAC-protected requests, even with the alias response protection set to `pbe`. RFC 9483 section 3.2 asks for the same kind of protection in every message of an operation, so certrally warns and `--profile strict` stops the enrollment.
* Error messages are unprotected. certrally shows the reason and marks the answer as not authenticated.
* General messages are rejected with `badRequest` "Can not handle message type '21'", so `cacerts` and `cmp genm` fail. `ping` still reports a CMP answer, but with `--ca-cert` it cannot check the unprotected answer and exits with status 4.
* In the tested setup EJBCA signed revocation responses with its ManagementCA instead of the CA that issued the certificate. With only the issuing CA in `--ca-cert`, `revoke` exits with status 4 although EJBCA has revoked the certificate. Put both CA certificates in `--ca-cert`.
* A `cr` signed with an end entity certificate is rejected with "Status NEW, FAILED or INPROCESS required" once the end entity has a certificate. Reset the end entity status in EJBCA first.
* Composite ML-DSA keys were rejected with "Illegal key algorithm, not authorized by certificate profile", even with the composite algorithms listed in the certificate profile.

## OpenSSL 4.0.3 `openssl cmp` mock server

* The server accepts only PasswordBasedMac. It answers a PBMAC1-protected request with `badRequest` "no suitable sender cert", and certrally suggests `--mac pbm`.
* Its `kup` carries only the server certificate. Without `--ca-cert`, certrally cannot verify the new certificate and asks for the issuing CA certificate.
* The server process exits on `cmp genm template` and `cmp genm rootupdate` unless it is started with the options for them, `-ref_cert` and `-rsp_newwithnew`.
