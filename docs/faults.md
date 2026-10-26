# Testing a CA with faulty messages

`certrally enroll --fault NAME` and `certrally poll --fault NAME` send a deliberately wrong message to test how a CA copes. It is the mirror of the fault flags of [`certrally mock`](mock.md), which test how a client copes. These flags exist to test CAs. Use them against a test CA or with the consent of the CA operator, because a CA may revoke or keep a certificate whose confirmation failed.

```bash
certrally enroll --server http://127.0.0.1:8080/.well-known/cmp --ref demo \
  --subject CN=device-42 --fault wrong-cert-hash --cert-out device.pem --key-out device.key
```

```text
✗ The certificate was issued but the confirmation failed
  Error   pkicmp: status rejection, failInfo: badCertId, details: certHash mismatch
  Saved   device.key, device.pem
  Note    The CA may keep or revoke this certificate. Check with the CA before retrying, because a retry can issue a second certificate.
  Faults  wrong-cert-hash (certConf)
```

A refusal by the CA is the expected outcome. The exit status follows the usual [rules](../README.md#exit-status): 3 when the CA rejects a request or a `pollReq`, 4 when its answer breaks the protocol or fails verification and 5 when it refuses the `certConf` of an issued certificate. certrally saves the certificate in every case it receives one. The `Faults` field of the report names each fault and the messages it changed. A fault that found no message to change, such as a `certConf` fault after the CA granted implicit confirmation, shows `(not sent)`. With `--json` the document holds the same list in [`faults`](json.md#document).

## Faults

`--fault` is repeatable. Faults that change the same message combine, for example a wrong certHash in a `certConf` without protection. "Later messages" are every message after the first request: `popdecr`, `pollReq` and `certConf`.

| Name | What certrally sends | RFC 9483 rule | Answer of `certrally mock` |
| --- | --- | --- | --- |
| `reject-certificate` | A `certConf` that rejects the certificate with status rejection | None. Section 3.6.1 lets an end entity reject a certificate. Section 4.1.1 asks the CA to answer `pkiConf` and to handle the certificate as rejected | `pkiConf`. The log notes `certificate rejected` |
| `wrong-cert-hash` | A `certConf` whose certHash does not match the issued certificate | Section 4.1.1 defines certHash. Section 5.1.2 asks the CA to check it (failInfo badCertId) | badCertId, `certHash mismatch` |
| `wrong-cert-req-id` | A `certConf` with a certReqId the response did not use | Section 4.1.1: the certReqId MUST be 0. Section 5.1.2 (failInfo badCertId) | badCertId, `certReqId does not match the issued certificate` |
| `reuse-sender-nonce` | Later messages repeat the senderNonce of the first request | Section 3.1: the senderNonce MUST be fresh. Section 3.5 does not ask the receiver to detect a reused one | Accepted. With `--strict` it refuses the `pollReq`, `popdecr` or `certConf` with badSenderNonce, `senderNonce reused` |
| `stale-recip-nonce` | Later messages carry a recipNonce that is not the senderNonce of the last response | Sections 3.1 and 3.5 (failInfo badRecipientNonce) | badRecipientNonce, `recipNonce mismatch` |
| `wrong-transaction-id` | Later messages carry another transactionID | Section 3.1: the transactionID MUST be the value of the previous message. Section 3.5 (failInfo badRequest) | badRequest, `unknown transaction` for a `certConf` and `no pending certificate` for a `pollReq` |
| `no-protection` | A `certConf` without protection | Section 3.5: messages without protection MUST be rejected | badMessageCheck, `message not protected` |
| `late-certconf` | A `certConf` after the confirmWaitTime of the response | Section 4.1.1: a CA that does not receive the `certConf` in time MUST handle it like a rejection | badRequest, `certConf after confirmWaitTime`. The log notes `certificate not confirmed in time` |

`reject-certificate` exits with status 0 when the CA answers `pkiConf`. The report then says that the certificate was issued and rejected. `confirmed` is `false` in the JSON result.

## Faults in a later poll

`certrally poll --fault` sends the faults in the messages of a transaction that `enroll --poll-later` left waiting, or that `enroll` stopped polling at `--timeout`:

```bash
certrally enroll --server http://127.0.0.1:8080/.well-known/cmp --ref demo --subject CN=device-42 \
  --poll-later --capture run.jsonl --cert-out device.pem --key-out device.key
certrally poll --transaction-id 5d41402abc4b2a76b9719d911017c592 --capture run.jsonl --fault stale-recip-nonce
```

The faults change the `pollReq` and `certConf` messages that `poll` sends. `reuse-sender-nonce` repeats the senderNonce of the request that the CA keeps waiting, which the capture file records. A `pollReq` that the CA refuses leaves the transaction recorded as waiting, so a `poll` without `--fault` can still collect the certificate. `certrally mock --waiting 1` keeps a request waiting for one poll.

## Waiting past confirmWaitTime

`late-certconf` waits until the confirmWaitTime of the response has passed, plus two seconds, because the GeneralizedTime in the response drops the fraction of a second. A response without confirmWaitTime gives no deadline, so `--confirm-delay` sets the wait:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \
  --secret-file secret.txt --subject CN=device-42 \
  --fault late-certconf --confirm-delay 2m --cert-out device.pem --key-out device.key
```

Without `--confirm-delay` such a response ends the run before the `certConf` with exit status 5. The certificate is saved. A wait that would end after `--timeout` fails the same way, so raise `--timeout` for a long confirmWaitTime. `certrally mock --confirm-wait 1s` keeps the test short.

## Limits

* `enroll --fault` cannot be combined with `--poll-later`, because the first request is the only message that run sends. Give `--fault` to `poll` instead.
* `--confirm-delay` needs `--fault late-certconf`.
* certrally checks each answer as usual, against the message as it was sent.
