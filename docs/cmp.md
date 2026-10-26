# CMP details

The [README](../README.md#enroll-a-certificate) shows a first enrollment, a key update and a revocation. This page covers the other CMP options and commands. [keys.md](keys.md) describes key types, encrypted keys and DER output, which work the same for CMP and EST.

## Protection

Shared-secret requests are protected with PBMAC1. The request header names `CN=<ref>` as the sender and `<ref>` as the key identifier, as RFC 9483 asks.

* `--mac pbm` selects PasswordBasedMac for CAs that accept only that, such as Nokia NCM, Insta Certifier and the `openssl cmp` mock server.
* `--iterations` sets the MAC iteration count (default 10000).
* `--hash sha1|sha256|sha384|sha512` selects the digest of the signatures certrally makes with an RSA or ECDSA key: the message protection with `--cert`, the proof of possession and a PKCS#10 request. With `--mac pbm` it also selects the one-way function and HMAC of the MAC. PBMAC1 always uses SHA-256. The default follows the key type. CAs refuse SHA-1 unless configured to accept it.

`--hash`, `--iterations` and `--general-info` also apply to `revoke` and the `genm` commands.

Requests use CMP version 2, the syntax of RFC 4210, so servers built for RFC 4210 understand them. Only messages that need a field added by RFC 9810 use version 3, such as the confirmation of a certificate that the CA signed with ML-DSA or composite ML-DSA.

## Certificate contents

Without `--subject` or `--san` a shared-secret request asks for a certificate for `CN=<ref>`.

`--key-usage` and `--ext-key-usage` ask for the keyUsage and extendedKeyUsage extensions, as comma-separated lists such as `--key-usage digitalSignature,keyEncipherment --ext-key-usage serverAuth,clientAuth`. Names are not case-sensitive.

* `--key-usage` takes `digitalSignature`, `nonRepudiation` (or `contentCommitment`), `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly` and `decipherOnly`. keyUsage is marked critical, as RFC 5280 recommends.
* `--ext-key-usage` takes `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`, `anyExtendedKeyUsage`, `cmcRA` or a dotted OID.

The CA decides what the certificate gets. Many CAs take the key usages from their profile instead.

`--template-cert device.pem` copies the subject, subjectAltName, keyUsage and extendedKeyUsage of an existing certificate, to request one shaped like a certificate the CA already issued. `--subject`, `--san`, `--key-usage` and `--ext-key-usage` replace the part they set. A `kur` already repeats the certificate in `--cert`, so it does not take `--template-cert`. A `p10cr` built by certrally carries these extensions in its PKCS#10 request. A request given with `--csr` cannot be changed.

## Header fields

`--general-info OID:int:N`, `OID:str:TEXT` or `OID:hex:DER` (repeatable) adds an item to the generalInfo field of the request header, for example a vendor profile identifier that a CA keys its policy on.

`--cert-req-id N` sets the certReqId of an `ir`, `cr` or `kur` (default 0), which the CA must repeat. RFC 9483 requires 0, so most CAs refuse other values.

## Implicit confirmation

`--implicit-confirm` asks the CA for implicit confirmation, as RFC 9483 recommends. A CA that grants it repeats `implicitConfirm` in its response and certrally skips the `certConf` exchange, so the run ends with the response. A CA that wants the confirmation leaves it out and certrally confirms as usual. The result says which happened.

## Collect a certificate later

A CA that needs approval answers with status `waiting`. `enroll` then polls until the CA decides or `--timeout` ends, 5 minutes by default. With `--poll-later` it stops at that answer instead, saves the new key and records the transaction in the `--capture` file:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt --subject CN=device-42 \
  --cert-out device.pem --key-out device.key \
  --poll-later --capture device.jsonl
```

```text
✓ Request waiting for the CA
  Status          waiting
  Transaction ID  d503c4aad8beeb7b34b820adb1809771
  Saved           device.key
  Note            Collect the certificate with: certrally poll --transaction-id d503c4aad8beeb7b34b820adb1809771 --capture device.jsonl
```

`poll` collects the certificate later, also from another directory. It takes the server, the protection, the trusted CA certificates and the output files from the capture file and reads the shared secret again. A run that signed with an encrypted key takes `--key-password-file` the same way. It polls until the CA decides, confirms the certificate and saves it:

```bash
certrally poll --transaction-id d503c4aad8beeb7b34b820adb1809771 \
  --capture device.jsonl --secret-file secret.txt
```

* A poll that ends at `--timeout` while the CA still waits records the new state, so the same command can run again. An `enroll` whose polling ends at `--timeout` records the transaction the same way when it has `--capture`.
* `--server`, `--cert-out`, `--chain-out`, `--key-out`, `--out-format`, `--ra-cert` and `--ra-key` replace the values from the capture file.
* Once the CA issues the certificate or rejects the request, the transaction ends and `poll` refuses it. After other failures, such as a wrong shared secret, the same command can run again.

## ML-KEM keys

ML-KEM-768 and ML-KEM-1024 keys cannot sign, so they cannot prove possession of the private key with a signature. For them `enroll` proves possession by decryption instead (RFC 9810 section 5.2.8.3), with `ir`, `cr` and `kur`:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt --subject CN=device-42 \
  --key-type ml-kem-768 --cert-out device-kem.pem --key-out device-kem.key
```

* `--pop encrypted-cert`, the default, asks the CA to encrypt the certificate for the key. certrally decrypts it. Its `certConf` proves that it could.
* `--pop challenge` asks the CA for a challenge encrypted for the key, which certrally answers before the CA issues the certificate.

The CA must offer the method. `certrally mock --accept encrypted-cert-pop --accept challenge-pop` offers both. `--pop` with a key that can sign is an error. A `p10cr` needs a key that signs. The result names the method in the `Proof of possession` field.

The key is saved in the seed form of RFC 9935, which OpenSSL 3.5 and later read. `--new-key` takes the forms OpenSSL writes, but not a key saved without its seed. `poll` needs the key to decrypt a waiting certificate: it reads the file that `enroll` saved or read. `--new-key` names the key when it is in another file.

## Let the CA generate the key

A device that cannot generate a good key pair itself can ask the CA for one (RFC 9483 section 4.1.6). `--central-keygen` sends a request without a public key. The CA generates the key pair, certifies it and returns the private key with the certificate, signed by a key generation authority and encrypted for the requester. certrally saves it to `--key-out`:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt --subject CN=device-42 \
  --central-keygen --cert-out device.pem --key-out device.key
```

Without `--key-type` the CA chooses the key type. `--key-type ecdsa-p384` asks for one. The CA may refuse it with `badAlg`. An RSA request cannot name the key size, so `rsa-3072` and `rsa-4096` ask for an RSA key of the size the CA chooses.

* It works with `ir`, `cr` and `kur`. A `p10cr` is signed with the new key, so it cannot ask for one. `--new-key` and `--pop` cannot be combined with `--central-keygen`.
* The CA encrypts the key to the shared secret or to the key in `--key`. That key must be RSA or ECDSA, because the other key types cannot decrypt.
* certrally saves the key only after it checked that the signature of the key generation authority verifies, that its certificate chains to a [trusted CA](#trust-and-connections) and may sign keys and that the key belongs to the certificate. Otherwise it rejects the certificate in its `certConf`. The result names the authority in the `Key generated by` field.
* The key is saved as PKCS#8 like other keys, as the CA encoded it, which may include its public key.
* With `--poll-later` the key arrives with the certificate, so `enroll` saves nothing. `poll` saves the key to the `--key-out` that `enroll` named unless its own `--key-out` names another file. It needs the same shared secret or `--key` to decrypt the key.

`certrally mock` generates every key type that `--key-type` offers, with 2048 bits for RSA.

## Forward requests as a registration authority

A registration authority (RA) checks requests before the CA sees them and vouches for them with its own signature. With `--ra-cert` and `--ra-key` certrally acts as the RA (RFC 9483 section 5.2.2.1). It wraps every request in a `nested` message that it signs with the RA certificate, including the `certConf` and each `pollReq`. The request inside keeps its own protection, here the shared secret of the device:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt --subject CN=device-42 \
  --ra-cert ra.pem --ra-key ra.key --cert-out device.pem --key-out device.key
```

* The CA must accept the RA, usually by the `cmcRA` extended key usage of its certificate (id-kp-cmcRA). `--ext-key-usage cmcRA` asks for one.
* `--ra-cert` may hold the chain after the RA certificate. certrally sends all of them in `extraCerts`.
* The CA answers the request inside, so the diagram shows `nested(ir)` and then a plain `ip`. The result names the RA in the `Forwarded by` field.
* certrally sends one request per `nested` message. It does not batch requests.
* `poll` forwards its requests through the RA that `enroll` used unless its own `--ra-cert` and `--ra-key` name another one.

`certrally mock` accepts an RA whose certificate it issued with `cmcRA`. `certrally mock --require-ra` refuses requests that no RA forwarded, except a request for an RA certificate.

## Trust and connections

certrally trusts the CA certificates in the first response from the server and the CA certificates in the `--cert` file, then checks every response against them. The report lists each certificate trusted from the first response with its SHA-256 fingerprint. If a response does not carry the CA certificate that issued the new certificate, pass that certificate with `--ca-cert`.

With `--ca-cert ca.pem` (repeatable) certrally trusts nothing the server sends. Signed responses and issued certificates must chain to a CA certificate from `--ca-cert` or `--cert`.

`--chain-out` holds the CA certificates that signed the new certificate and each other, as far as the response carries them. A certificate that only carries the name and key identifier of an issuer is left out, since nothing protects the extraCerts of a response.

Over HTTPS the server is checked against the system roots or against the CA certificates in `--tls-ca-cert`. `--insecure` skips that check, for a test server with a self-signed certificate. certrally then warns that anyone who intercepts the connection can pose as the server. The capture file records it. `--insecure` cannot be combined with `--tls-ca-cert`. Over plain HTTP nothing authenticates the first response, so certrally warns when it trusts one.

certrally connects through the proxy that the `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` environment variables name, like other HTTP clients. `--proxy http://proxy.example.com:3128` names a proxy on the command line instead, on every command that talks to a server. An `https` proxy works too. Credentials in the URL are sent to the proxy.

## Revoke by serial number

An authority that has no copy of the certificate names it with `--serial` and `--issuer`. `--serial` takes a decimal number, hex with `0x` or the colon-separated hex that certrally prints. `--invalidity-date` tells the CA when the key was compromised or the certificate became invalid, as RFC 3339 or `YYYY-MM-DD`, for the CRL entry:

```bash
certrally revoke --server https://ca.example.com/.well-known/cmp \
  --ref ra-1 --serial 0x1A2B --issuer 'CN=Example CA' --reason keyCompromise --invalidity-date 2026-10-01
```

## Ask the CA for information

`cacerts` and the `cmp genm` commands send the RFC 9483 support messages. They are protected like enroll requests:

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --out ca-certs.pem
```

| Command | Answer |
|---|---|
| `cacerts` or `cmp genm cacerts` | The CA certificates. `--out` saves them |
| `cmp genm rootupdate --old-root root.pem` | The new root CA certificate, if the root has been replaced. It is accepted only when the old root certifies it |
| `cmp genm template` | The subject, extensions and key types the CA expects. `--cert-profile` selects a profile |
| `cmp genm crl` | The current CRL. Its signature is checked against the trusted CA certificates |
| `cmp genm crlupdate --crl ca.crl` | A CRL newer than `ca.crl`. `--crl-issuer ca.pem` asks for any CRL from that CA instead |
| `cmp genm raw caCerts` | The answer to any info types, given by name or as dotted OIDs |

`--out -` writes the certificates or the CRL to standard output and moves the summary to standard error. `--out-format der` writes DER, with several certificates as PKCS#7.

## Check a server

`ping` sends an unprotected general message and reports who answers and how fast. It needs no credentials, because any CMP answer counts, including the error a CA sends back for an unprotected request:

```bash
certrally ping --server https://ca.example.com/.well-known/cmp --count 3
```

```text
  1  error rejection badMessageCheck  ECDSA SHA-256  690 B  12.4 ms
  2  error rejection badMessageCheck  ECDSA SHA-256  689 B  9.8 ms
  3  error rejection badMessageCheck  ECDSA SHA-256  688 B  10.1 ms
✓ The server answers CMP
  Server      https://ca.example.com/.well-known/cmp
  Answer      error rejection badMessageCheck
  CA says     "message not protected"
  Sender      CN=Example CA
  Protection  ECDSA SHA-256
  Round trip  min 9.8 ms, avg 10.8 ms, max 12.4 ms
  Replies     3 of 3
  Note        An error is the expected answer, because the request carries no protection.
```

With `--ca-cert` the answer must also be signed by that CA. A CA that leaves its errors unprotected fails this check.

## Test how a CA copes with faulty messages

`--fault NAME` makes `enroll` and `poll` send a deliberately wrong message, such as a `certConf` with a wrong certHash or a request that reuses a nonce. Use it against a test CA or with the consent of the CA operator. [faults.md](faults.md) lists the faults, the RFC 9483 rule each one breaks and how `certrally mock` answers it.
