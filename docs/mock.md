# The CMP test CA

The [README](../README.md#try-it-with-a-test-ca) introduces `certrally mock`, a CMP test CA for trying certrally and test scripts without a real CA. This page describes what it does and the fault flags that make it delay, reject or confirm requests differently and accept deviations from RFC 9483, to test how a client copes.

## What it does

`certrally mock` listens on `127.0.0.1:8080` (`--listen`) and answers at `/.well-known/cmp`. It issues certificates for `ir`, `cr`, `kur` and `p10cr`, confirms and revokes them and answers the requests for CA certificates, a request template and CRLs. It accepts the shared secret for `--ref` (default `demo`) and signatures made with certificates it issued. The secret comes from `--secret-file` or `CERTRALLY_SECRET`. Without either, a random secret is generated and printed. `--ca-out` saves the CA certificate for `--ca-cert`. Everything lives in memory and is lost when the CA stops.

The startup report shows the address, the CA name, the secret source and the fault flags in use, then an `enroll` command that works against the CA. Every request is logged on one line: the time, the request body and its protection, the response and how long it took.

## Delayed answers

`--waiting N` answers each certificate and revocation request with status `waiting` and decides it on the Nth poll. `--check-after` sets the time the response tells the client to wait before it polls (default 1s). certrally polls when asked and waits at least one second between polls.

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

`--grant-implicit-confirm` grants implicit confirmation to a request that asks for it, so that client need not send `certConf`. A request that does not ask for it is confirmed as usual. certrally never asks for implicit confirmation, so use the flag with clients that do, such as `openssl cmp -implicit_confirm`.

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

`mac-revocation` authorizes every such request, because the test CA has no revocation policy of its own. `encrypted-cert-pop` and `challenge-pop` serve clients that prove possession without a signature. certrally always signs its proof of possession.

```bash
certrally mock --strict --mac-iterations 100-10000 --accept sha1
```
