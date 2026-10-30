# JSON output and capture files

certrally can describe its work in JSON for scripts. It can also record the CMP, EST and SCEP messages of a run for later inspection.

* `--json` prints the outcome of one command as a JSON document on standard output.
* `--capture FILE` appends every message of a run, with its bytes, to a JSON Lines file.

Later versions may add fields. Existing fields keep their names and meaning.

## Conventions

* Names are RFC 4514 strings, such as `CN=device-42,O=Example`, with the attributes in their encoded order. Attribute types other than CN, O, OU, C, L, ST, STREET, POSTALCODE, SERIALNUMBER, UID and DC appear as dotted OIDs.
* Times are RFC 3339 in UTC.
* Message bytes and info type values are base64. Transaction IDs, key identifiers, SCEP nonces and fingerprints are lower-case hex. A SCEP transaction ID is the string of the message, which certrally sends as 40 upper-case hex digits. Certificate serial numbers are upper-case hex.
* Certificates, CRLs, public keys and requests are PEM strings. Private keys never appear in JSON output or capture files.
* Text from the server, such as `statusText`, is kept as the server sent it.

## JSON output

`--json` works with `enroll`, `poll`, `revoke`, `cacerts`, `cmp genm` and its subcommands, `ping`, `inspect`, `lint`, `keygen`, the `est` commands except `est mock` and the `scep` commands except `scep mock`. Standard output then holds exactly one JSON document, whatever the outcome. The ladder diagram and the text report are not printed. The exit status is the same as without `--json`.

When certrally cannot parse the command line, for example because of an unknown flag or a missing required flag, the document holds the error and the error is also printed on standard error. `--json` cannot be combined with `--quiet` or with an output file of `-`.

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \
  --cert-out device.pem --key-out device.key --json | jq -r .result.certificate.notAfter
```

### Document

| Field | Type | Meaning |
|---|---|---|
| `command` | string | The command as it was typed, such as `enroll`, `cmp enroll`, `cmp genm crl` or `est enroll` |
| `ok` | boolean | `true` when the exit status is 0 |
| `exitStatus` | number | The exit status of the process |
| `server` | string | The `--server` URL without any password. Absent when the command does not contact a server or stops before it does |
| `profile` | string | The [response profile](profiles.md), `compatible` or `strict`. Absent when `server` is absent |
| `exchange` | array | One [message record](#message-records) per request, response or failure, and per connection of an EST command, in order. Absent when nothing was sent |
| `result` | object | The [result](#results) of the command. Present on success and with some failures |
| `error` | object | The [error](#errors) when `ok` is `false` |
| `faults` | array | One entry per [`enroll` or `poll --fault`](faults.md) value, in the order of the help text. `name` is the fault and `messages` lists the body types it changed, such as `certConf`. An empty `messages` means the fault found no message to change. Absent without `--fault` |
| `trustedOnFirstResponse` | array | The certificates a CMP command trusted from its first response or a SCEP command from its GetCACert answer, each with the fields of a certificate in a [result](#results), so that `sha256` can be compared with the fingerprint the CA published. Absent with `--ca-cert` or `--fingerprint`, on the EST commands and on `poll` and `scep poll`, which keep the trust of the enrollment |
| `warnings` | array of strings | Problems that did not fail the command, such as a CRL signature that does not verify or a response that breaks a rule of the `compatible` profile |

An enrollment produces a document like this, shortened:

```json
{
  "command": "enroll",
  "ok": true,
  "exitStatus": 0,
  "server": "https://ca.example.com/.well-known/cmp",
  "profile": "compatible",
  "exchange": [
    {"kind": "request", "time": "2026-10-13T01:39:22.235769Z", "size": 486, "body": "ir", "protection": "PBMAC1", "sender": "CN=device-42", "transactionId": "95a9cb74b5c4c3cfd5a4040906e3756b", "senderKid": "6465766963652d3432"},
    {"kind": "response", "time": "2026-10-13T01:39:22.240007Z", "elapsedMs": 4.238, "httpStatus": 200, "contentType": "application/pkixcmp", "size": 1481, "body": "ip", "protection": "PBMAC1", "sender": "CN=Example CA", "status": "accepted", "extraCerts": 1},
    {"kind": "request", "body": "certConf"},
    {"kind": "response", "body": "pkiconf"}
  ],
  "result": {
    "status": "accepted",
    "confirmed": true,
    "certificate": {"subject": "CN=device-42", "issuer": "CN=Example CA", "serial": "EE460F82A9CD474DAED4950B232DC3B8", "notBefore": "2026-10-13T01:38:22Z", "notAfter": "2027-10-13T01:39:22Z", "key": "ECDSA P-256", "sha256": "a79eb735...", "pem": "-----BEGIN CERTIFICATE-----\n..."},
    "chain": [{"subject": "CN=Example CA"}],
    "saved": ["device.key", "device.pem"]
  }
}
```

An EST enrollment records its connection, the request and the response:

```json
"exchange": [
  {"kind": "connect", "time": "2026-10-21T13:09:59.716Z", "size": 0, "tls": {"version": "TLS 1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256", "server": "CN=est.example.com"}},
  {"kind": "request", "time": "2026-10-21T13:09:59.717Z", "size": 334, "method": "POST", "path": "/.well-known/est/simpleenroll", "operation": "simpleenroll", "content": "pkcs10", "subject": "CN=device-42"},
  {"kind": "response", "time": "2026-10-21T13:09:59.719Z", "elapsedMs": 1.9, "httpStatus": 200, "contentType": "application/pkcs7-mime; smime-type=certs-only", "size": 588, "operation": "simpleenroll", "content": "certs-only", "certificates": 1}
]
```

### Message records

| Field | Meaning |
|---|---|
| `kind` | `request`, `response`, `failure` or `connect`. A failure is a request that got no HTTP response, or an EST connection that failed. A `connect` record describes a TLS connection of an EST command |
| `time` | When the request was sent or the response or failure arrived |
| `elapsedMs` | Round-trip time of a response or failure in milliseconds |
| `httpStatus`, `contentType` | The HTTP status and content type of a response |
| `size` | Body size in bytes |
| `body` | The PKIBody type, such as `ir`, `ip`, `genp` or `error`. Absent when the body is not a CMP message |
| `nested` | The body types of the messages in a `nested` body, such as `["ir"]` for a request that a registration authority forwards |
| `protection` | The protection algorithm, such as `PBMAC1` or `ML-DSA-65`. It is `none` for an unprotected message |
| `sender` | The sender name in the header |
| `transactionId`, `senderKid` | Header fields, as hex |
| `status`, `failInfo`, `statusText` | The first PKIStatusInfo of an `ip`, `cp`, `kup`, `rp` or `error` body. `failInfo` lists the failure bit names. For SCEP, the pkiStatus of a CertRep, `SUCCESS`, `PENDING` or `FAILURE`, and the failInfo name |
| `checkAfter` | The seconds a `pollRep` asks the client to wait |
| `extraCerts` | The number of certificates in `extraCerts` |
| `method`, `path`, `operation` | The HTTP method and path of an EST request and its EST operation, such as `simpleenroll`. A SCEP request has the method and its SCEP operation, such as `GetCACert` or `PKIOperation`. Responses also carry `operation` |
| `caName` | The CA name that a SCEP request sends in its `message` parameter |
| `messageType`, `senderNonce`, `recipientNonce` | The message type of a SCEP pkiMessage, such as `PKCSReq` or `CertRep`, and its nonces |
| `digest`, `cipher` | The signature digest and the content cipher of a SCEP pkiMessage, such as `SHA-256` and `AES-128-CBC` |
| `capabilities` | The capabilities of a SCEP GetCACaps answer |
| `content` | The EST message in the body: `pkcs10`, `certs-only`, `csrattrs` or `serverkeygen`. Absent for a body that is not one of them, such as an error |
| `subject` | The subject of an EST PKCS#10 request |
| `certificates` | The number of certificates in an EST `certs-only` response, in the certificate part of a `serverkeygen` response or in a SCEP certificate answer |
| `retryAfter` | The seconds the `Retry-After` header of an EST or SCEP response asks for |
| `parts` | The parts of an EST `serverkeygen` response, each with `contentType` and `size`. The key part is never decoded or stored |
| `text` | The text of an EST or SCEP error response, as the server sent it. For a SCEP error page in HTML, the text of the page without its markup |
| `tls` | The connection of a `connect` record: `version`, `cipherSuite`, `server` with the subject of the server certificate and `srpUser` for a TLS-SRP sign-in |
| `problem` | Why a response cannot be a CMP, EST or SCEP answer (for example `HTTP 404 Not Found`), why its EST message does not decode or why a request failed |
| `der` | The message bytes. For EST, the decoded body, and for `serverkeygen` only its certificate part. For SCEP, the pkiMessage of a request, also when it travels in the URL, or the body of a response. Only capture files include them |

### Errors

| Field | Meaning |
|---|---|
| `title` | One line that says what failed, as in the text report |
| `message` | The underlying error |
| `status`, `failInfo`, `statusText` | The CA status of a rejection |
| `httpStatus`, `retryAfter` | The HTTP status and `Retry-After` seconds of an EST or SCEP refusal. `statusText` then holds the text of the server |
| `unauthenticated` | `true` when certrally could not verify the rejection, so any peer on the path could have sent it |
| `hint` | What to check or change, when certrally can tell |
| `note` | More context, such as advice for an issued but unconfirmed certificate |

### Results

A certificate in a result has `subject`, `issuer`, `serial`, `notBefore`, `notAfter`, `altNames`, `key`, `sha256` and `pem`. A command run under `cmp`, such as `cmp enroll`, has the result of the same command without the prefix.

| Command | Result fields |
|---|---|
| `enroll`, `poll` | `status`, `confirmed`, `implicitConfirm`, `certificate`, `chain`, `saved`, `transactionId`. With exit status 5 the result is present and `confirmed` is `false`. `confirmed` is also `false` after `--fault reject-certificate`, which rejects the certificate. `implicitConfirm` is `true` when the CA granted implicit confirmation, so no `certConf` was sent. `proofOfPossession` is `encrypted-cert` or `challenge` for a key that cannot sign, such as an ML-KEM key, and absent otherwise. `centralKeyGeneration` is `true` and `keyGenerationAuthority` names the signer of the key when the CA generated the key with `--central-keygen`. Both are absent otherwise. `registrationAuthority` is the subject of the `--ra-cert` certificate that forwarded the requests, absent without one. When the CA keeps the request waiting, under `enroll --poll-later` or when polling ends at `--timeout` with `--capture`, `status` is `waiting`, `certificate` is `null`, `saved` lists only a new key and `nextPoll` tells when the CA asked for the next poll, if it did |
| `revoke` | `certificate`, `issuer`, `serial`, `reason`, `invalidityDate`. `certificate` is `null` when the certificate was named with `--serial` and `--issuer`. `invalidityDate` is present when `--invalidity-date` was given |
| `cacerts`, `cmp genm cacerts` | `certificates`, `saved` |
| `cmp genm rootupdate` | `update` with `newWithNew`, `newWithOld` and `oldWithNew`. It is `null` when no update is available. `saved` |
| `cmp genm template` | `template` with `subject`, `extensions` and `keyTypes`. It is `null` when the CA imposes nothing. An attribute without a value in `subject` is one the requester fills in. Each extension has `oid`, `name` and `critical` |
| `cmp genm crl`, `cmp genm crlupdate` | `crl` with `issuer`, `thisUpdate`, `nextUpdate`, `number`, `revoked`, `signature` and `pem`. It is `null` when there is none. `signature` is `valid`, `invalid` or `unchecked`. `saved` |
| `cmp genm raw` | `items`, each with `infoType`, `oid` and `value` |
| `ping` | `sent`, `answered`, `sender`, `protection`, `rttMs` with `min`, `avg` and `max`. With `--ca-cert`, `verified` tells whether every answer was signed by that CA |
| `keygen` | `keyType`, `key`, `publicKey`, `csr`, `saved`. With `--list`, `keyTypes` |
| `est cacerts` | `certificates`, `saved` and `verified`, which says how the certificates were checked: `tls` by the TLS certificate of the server, `srp` by a TLS-SRP sign-in, `fingerprint` by `--fingerprint`, `confirmed` by a person at the prompt or `none` after `--bootstrap` or `--insecure`. `tlsIssued` tells whether the trusted certificates issued the TLS certificate of the server. `unverified` lists the received certificates that the fingerprint check did not cover, which are not saved, and is absent otherwise |
| `est csrattrs` | `attributes`, each with `oid`, `name` when certrally knows one and `values` for an attribute that has them |
| `est enroll`, `est reenroll`, `est serverkeygen` | `certificate`, `key` with the type of a new key and `saved`. `key` is absent when `--new-key` or `--csr` supplied the key |
| `scep caps` | `capabilities`, the `digest`, `cipher` and `method` that certrally picks from them, and `renewal` and `nextCACert`, which tell whether the server lists Renewal and GetNextCACert |
| `scep cacert`, `scep chain`, `scep nextca` | `certificates`, each also with `sha1` and, except for `scep chain`, `roles`: `issuing CA`, `RA encryption`, `RA signature` or `other`. `ca` is the issuing CA, absent for `scep chain`. `saved`, and `verified`, which says how the certificates were checked: `tls`, `fingerprint`, `signed` by the current CA for `scep nextca` or `none`. `unverified` lists the received certificates that the fingerprint check did not cover, which are not saved |
| `scep enroll`, `scep renew`, `scep poll` | `status` (`SUCCESS` or `PENDING`), `messageType`, `transactionId`, `digest`, `cipher`, `certificate`, `chain`, `key` with the type of a new key, `state` with the state file of a pending request, `polls` with the number of CertPoll requests sent and `saved` |
| `scep getcert` | `certificates`, `saved` |
| `scep getcrl` | `crl` as for `cmp genm crl`, `saved` |
| `inspect` | `messages`, one [inspected message](#inspected-messages) per message in file order |
| `lint` | `checked` and `skipped` count the responses checked and those left unchecked: CMP responses without a request before them and EST and SCEP responses outside capture files. `findings` lists each deviation with `source`, `body` (the CMP body type or the EST or SCEP operation), `text` and `rule`. With exit status 6 the result is present |

`saved` lists the files written, in the order they were written.

### Inspected messages

| Field | Meaning |
|---|---|
| `source` | Where the message was read, such as `run.jsonl:4` for line 4 of a capture file, `ip.der` or `msgs.pem#2` for the second PEM block |
| `protocol` | `cmp`, `est` or `scep` |
| `direction` | `request` or `response`. A capture records it. For other files it follows from the body type, and only an EST PKCS#10 request is a request |
| `time`, `server` | When a capture recorded the message and the server of its run |
| `size`, `body` | The message size in bytes and, for CMP, the PKIBody type |
| `est` | The EST exchange: `operation`, `method`, `path`, `httpStatus`, `contentType`, `retryAfter`, `parts` and `text` as in [message records](#message-records) from a capture, and `content` |
| `scep` | The SCEP exchange from a capture: `operation`, `method`, `httpStatus`, `contentType`, `caName`, `messageType`, `transactionId`, `senderNonce`, `recipientNonce`, `status`, `failInfo`, `digest`, `cipher`, `capabilities`, `retryAfter` and `text` as in [message records](#message-records) |
| `header` | For CMP: `pvno`, `sender`, `recipient`, `messageTime`, `transactionId`, `senderNonce`, `recipNonce`, `senderKid`, `recipKid`, `freeText`, `generalInfo` with the info type names and `certProfile`. An empty `sender` or `recipient` is the NULL-DN |
| `protection` | For CMP: `algorithm`, `none` for an unprotected message. `check` is `valid`, `invalid` or `unchecked`, with the reason in `problem`. A MAC is `unchecked` without the shared secret. `signer` is the subject of the certificate whose signature verifies. With `--ca-cert`, `trusted` tells whether the signer chains to those certificates at the capture `time`, or at the time of the run for a message without one |
| `requests` | The requests of `ir`, `cr`, `kur`, `p10cr` and an EST PKCS#10 request: `certReqId` (absent for `p10cr` and EST), `subject`, `key`, `extensions`, `pop` (`signature`, `raVerified`, `keyEncipherment`, `keyAgreement` or `none`), `popSignature` and `popProblem` for a signature proof and `oldCert` with `issuer` and `serial` for a key update |
| `responses` | The responses of `ip`, `cp` and `kup`: `certReqId`, `status`, `failInfo`, `statusText`, `certificate` and `encrypted` when the certificate is encrypted |
| `caPubs`, `extraCerts` | Certificates |
| `revocations` | The entries of `rr` with `issuer`, `serial` and `reason`, or of `rp` with `status`, `failInfo`, `statusText` and, when the CA names the certificate, `issuer` and `serial` |
| `confirmations` | The entries of `certConf`: `certReqId`, `certHash`, `hashAlg` and the status. No status means the certificate is accepted |
| `polls` | The entries of `pollReq` with `certReqId`, or of `pollRep` with `certReqId`, `checkAfter` and `reason` |
| `error` | The content of an `error` body: `status`, `failInfo`, `statusText`, `errorCode` and `errorDetails` |
| `items` | The items of `genm` and `genp`, like those of `cmp genm raw` |
| `challenges` | The challenges of `popdecc`, which the CA sends for a key that proves possession by decryption: `owf`, `witness` and `encryptedRandSize`. Only the first challenge names the one-way function `owf` |
| `answers` | The decrypted numbers of `popdecr` in hex, in the order of the challenges |
| `nested` | The body types of the messages in a `nested` body |
| `certificates` | The certificates of an EST `certs-only` message or `serverkeygen` response, of a SCEP certificate answer or those that a SCEP pkiMessage carries |
| `attributes` | The EST CSR attributes, like those of `est csrattrs` |
| `problems` | Parts of the message that could not be decoded |

## Capture files

`--capture FILE` works with every command that talks to a server. It appends the run to `FILE` as JSON Lines, one JSON object per line:

1. A `start` line with `format` (currently 1), `tool`, `version`, `command`, `server` and `time`. A run of an EST or SCEP command adds `protocol` with the value `est` or `scep`. A run with `--insecure` adds `insecure` with the value `true`, because it did not check the TLS certificate of the server.
2. One [message record](#message-records) per request, response, failure or EST connection, including `der`.
3. A `transaction` line with `time`, `id`, `state` and `resume` when the run leaves a waiting transaction for `poll` (`state` is `waiting`) or `poll` ends one (`ended`). `id` is the transaction ID. `resume` holds what `poll` needs: the server, the protection settings and the names of their files, the trusted CA certificates, the output files with their format, the name of the key file when the CA encrypts the certificate for the key and the state of the CMP transaction. It holds no secret or private key. `poll` uses the last line of a transaction.
4. An `end` line with `time` and `exitStatus`.

Each run appends its own lines, so one file can hold several runs. Readers should skip lines of other kinds, which later versions may add. `--capture` works together with `--json` and `--quiet`. `certrally inspect` and `certrally lint` read capture files.

certrally creates the file with mode 0600. Keep capture files private: anyone who has the messages of a MAC-protected exchange can try to guess the shared secret offline.
