# Response profiles

certrally checks every CMP response against rules of the Lightweight CMP Profile (RFC 9483) and RFC 9810 that some CAs do not follow. `--profile` chooses what happens when a response breaks one of them:

| Profile | Effect |
|---|---|
| `compatible` | The default. certrally accepts the response and prints a warning that names the rule |
| `strict` | certrally stops the exchange before it accepts the response and exits with status 6 |

`--profile` works with every command that talks to a server. With `--json` the warnings appear in `warnings` and the profile in `profile`.

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --profile strict
```

Checks that keep the exchange secure do not depend on the profile. certrally always rejects a response with the wrong transaction ID, a recipient nonce that does not match the request or protection that does not verify.

Some CAs copy the `senderKID` of a signed request into their signed responses, so it names none of the certificates certrally could check the signature with. `compatible` then tries each of them. The signer must still chain to a trusted CA certificate and have the sender's name. `strict` stops such a response.

## Rejections and enrollment

A rejection from the CA ends the command with exit status 3 in both profiles. Rules that the rejection breaks are listed as warnings, because the reason the CA gives is more useful than the deviation.

When `strict` stops an `ip`, `cp` or `kup` response, certrally neither confirms nor saves the certificate. Depending on its policy, the CA revokes or keeps a certificate that is never confirmed. When `strict` stops the `pkiconf` that answers the confirmation, the CA has already issued and confirmed the certificate, so certrally saves it and exits with status 5.

## Rules

| Rule | Source |
|---|---|
| `pvno` is 2 or 3 | RFC 9483 section 3.5 |
| `senderNonce` is present and at least 128 bits long | RFC 9483 section 3.5 |
| Only `ip`, `cp` and `kup` carry `implicitConfirm` in `generalInfo` | RFC 9483 section 3.1 |
| `implicitConfirm` is granted only when the request asked for it. certrally never asks for it | RFC 9810 section 5.1.1.1 |
| `confirmWaitTime` comes with `messageTime` and never with `implicitConfirm` | RFC 9483 section 3.1 |
| No response carries `certProfile` | RFC 9483 section 3.1 |
| The response is protected the same way as the request: a MAC answers a MAC and a signature answers a signature. Error messages are exempt, because a CA signs them when it cannot check the request | RFC 9483 section 3.2 |
| A signed response has a `senderKID` when its protection certificate has a subject key identifier | RFC 9483 section 3.1 |
| The `senderKID` of a signed response is the subject key identifier of a certificate in `extraCerts` or among the trusted ones. It counts as broken only when one of those certificates has the sender's name and a subject key identifier | RFC 9483 section 3.1 |
| The first signed response of an operation starts `extraCerts` with its protection certificate. Error messages are exempt | RFC 9483 section 3.3 |
| An `ip`, `cp` or `kup` that issues a certificate carries `extraCerts` with the chain of the new certificate. A certificate issued directly by a self-signed CA certificate that certrally trusts or finds in `caPubs` needs none, because self-signed certificates are left out of `extraCerts` | RFC 9483 section 3.3 |
| An `error` message has the status `rejection`. While the CA prepares a certificate the status may be `waiting` | RFC 9483 section 3.6.4 |
| A `pkiconf` holds an ASN.1 NULL rather than nothing | RFC 9810 section 5.3.17 |

## Checking recorded runs

`certrally lint` applies the same rules to responses recorded with `--capture` or saved as message files. It exits with status 6 when a response breaks a rule and with 0 when none does.

```bash
certrally lint run.jsonl
```

Each response is checked as the answer to the request before it in the same run. Messages from other files form one exchange in command line order, such as `certrally lint ir.der ip.der certConf.der pkiconf.der`. Without `--ca-cert` the certificates in the first response of each exchange count as trusted, as they do during a run.

`lint` also checks what certrally enforces during a run, because messages from other clients have not been through those checks: each response carries the `transactionID` of its request (RFC 9483 section 3.1) and a `recipNonce` equal to the `senderNonce` of its request or, for a delayed response, of an earlier request of the same transaction (RFC 9483 section 3.5).
