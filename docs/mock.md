# The CMP test CA

The [README](../README.md#try-it-with-a-test-ca) introduces `certrally mock`, a CMP test CA for trying certrally and test scripts without a real CA. This page describes what it does and the fault flags that make it delay, reject or confirm requests differently and accept deviations from RFC 9483, to test how a client copes.

## What it does

`certrally mock` listens on `127.0.0.1:8080` (`--listen`) and answers at `/.well-known/cmp`. It issues certificates for `ir`, `cr`, `kur` and `p10cr`, confirms and revokes them and answers the requests for CA certificates, a request template and CRLs. It accepts the shared secret for `--ref` (default `demo`) and signatures made with certificates it issued. It copies the requested subject and extensions, such as subjectAltName and extendedKeyUsage, into the certificate, but always sets keyUsage to digitalSignature. For `enroll --central-keygen` it generates the key pair. That is ECDSA P-256 when the request leaves the choice to it and otherwise any type that `--key-type` offers, with 2048 bits for RSA. A key generation authority certificate that it issues at startup with the id-kp-cmKGA extended key usage signs the private key. It accepts requests that a [registration authority](#registration-authorities) forwards. The secret comes from `--secret-file` or `CERTRALLY_SECRET`. Without either, a random secret is generated and printed. `--ca-out` saves the CA certificate for `--ca-cert`. Everything lives in memory and is lost when the CA stops.

The startup report shows the address, the CA name, the secret source and the fault flags in use, then an `enroll` command that works against the CA. Every request is logged on one line: the time, the request body and its protection, the response and how long it took. A revocation adds a line below its request with the serial number, the reason and the invalidity date when the request gave one. A generated key pair adds a line with its key type. A forwarded request adds a line with the subject of the registration authority. The CRL lists the invalidity date too.

## Registration authorities

The test CA accepts a request that a registration authority (RA) forwards in a `nested` message, as `enroll --ra-cert` and `--ra-key` send it. The RA must sign the `nested` message with a certificate that the CA issued with the `cmcRA` extended key usage and has not revoked. Enroll one with `--ext-key-usage cmcRA`:

```bash
certrally enroll --server http://127.0.0.1:8080/.well-known/cmp --ref demo \
  --subject CN=ra --ext-key-usage cmcRA --cert-out ra.pem --key-out ra.key
```

Other RAs are refused with `notAuthorized` and a MAC-protected `nested` message with `wrongIntegrity`. Requests that no RA forwarded are accepted as usual. `--require-ra` refuses those with `notAuthorized`, except a request for a certificate with `cmcRA`, so that an RA can enroll.

```bash
certrally mock --require-ra
```

## Delayed answers

`--waiting N` answers each certificate and revocation request with status `waiting` and decides it on the Nth poll. `--check-after` sets the time the response tells the client to wait before it polls (default 1s). certrally polls when asked and waits at least one second between polls. `enroll --poll-later` and `poll` collect the certificate in a later run.

```bash
certrally mock --waiting 2 --check-after 5s
```

## Rejections

`--reject FAILINFO[:TEXT]` rejects every certificate and revocation request with the given failInfo and an optional statusString. With `--waiting` the rejection comes on the last poll.

```bash
certrally mock --reject badCertTemplate:'subject not allowed'
```

The failInfo names are those of RFC 9810 section 5.2.3, such as `badRequest`, `badCertTemplate`, `badPOP` or `systemUnavail`. Shell completion lists them.

## Confirmation

`--grant-implicit-confirm` grants implicit confirmation to a request that asks for it, so that the client need not send `certConf`. A request that does not ask for it is confirmed as usual. `certrally enroll --implicit-confirm` asks for it, as does `openssl cmp -implicit_confirm`.

`--confirm-wait` sets the time the client has to confirm a certificate, sent as `confirmWaitTime` (default 10s). The CA drops a transaction whose certificate is not confirmed in time.

## Profile checks

`--strict` refuses requests that break RFC 9483 instead of accepting the usual deviations, such as a missing transactionID, a NULL-DN sender or a reused senderNonce. It also overrides the `--accept` values that relax a rule of the profile.

`--mac-iterations MIN-MAX` accepts only shared-secret MACs whose iteration count is in the range. The default is 1 to 500000. Use it with `certrally enroll --iterations` to test the limits of a client.

`--accept NAME` (repeatable) accepts one deviation from the profile:

| Name | Accepts |
| --- | --- |
| `missing-pollreq-nonce` | a `pollReq` without recipNonce |
| `missing-certconf-nonce` | a `certConf` without recipNonce |
| `missing-subject` | a certificate template without subject |
| `any-cert-req-id` | a certReqId other than 0, repeated in the response |
| `missing-revocation-reason` | a revocation request without reason code |
| `missing-revocation-issuer` | a revocation request without issuer |
| `poposkinput` | a signature proof of possession over poposkInput |
| `signature-pop` | no proof of possession in a request signed with a certificate for the key |
| `sha1` | SHA-1 signatures in the protection and the proof of possession |
| `mac-revocation` | revocation requests not signed with the revoked certificate, such as MAC-protected ones |
| `raw-subject` | the subject as encoded in the request, keeping every attribute, order and string type |
| `encrypted-cert-pop` | the encrypted certificate proof of possession |
| `challenge-pop` | the challenge-response proof of possession |

`mac-revocation` authorizes every such request, because the test CA has no revocation policy of its own. `encrypted-cert-pop` and `challenge-pop` serve clients that prove possession without a signature, such as `enroll` with an ML-KEM key and `--pop encrypted-cert` or `--pop challenge`. The test CA certifies an ML-KEM key with keyEncipherment as its only key usage.

```bash
certrally mock --strict --mac-iterations 100-10000 --accept sha1
```
