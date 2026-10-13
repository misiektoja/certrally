# JSON output and capture files

certrally can describe its work in JSON for scripts. It can also record the CMP messages of a run for later inspection.

* `--json` prints the outcome of one command as a JSON document on standard output.
* `--capture FILE` appends every message of a run, with its bytes, to a JSON Lines file.

Later versions may add fields. Existing fields keep their names and meaning.

## Conventions

* Names are RFC 4514 strings, such as `CN=device-42,O=Example`.
* Times are RFC 3339 in UTC.
* Message bytes and info type values are base64. Transaction IDs, key identifiers and SHA-256 fingerprints are lower-case hex. Certificate serial numbers are upper-case hex.
* Certificates, CRLs, public keys and requests are PEM strings. Private keys never appear in JSON output or capture files.
* Text from the server, such as `statusText`, is kept as the server sent it.

## JSON output

`--json` works with `enroll`, `revoke`, `cacerts`, `cmp genm` and its subcommands, `ping` and `keygen`. Standard output then holds exactly one JSON document, whatever the outcome. The ladder diagram and the text report are not printed. The exit status is the same as without `--json`.

When certrally cannot parse the command line, for example because of an unknown flag or a missing required flag, the document holds the error and the error is also printed on standard error. `--json` cannot be combined with `--quiet` or with an output file of `-`.

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \
  --cert-out device.pem --key-out device.key --json | jq -r .result.certificate.notAfter
```

### Document

| Field | Type | Meaning |
|---|---|---|
| `command` | string | The command, such as `enroll` or `cmp genm crl` |
| `ok` | boolean | `true` when the exit status is 0 |
| `exitStatus` | number | The exit status of the process |
| `server` | string | The `--server` URL without any password. Absent when the command does not contact a server or stops before it does |
| `exchange` | array | One [message record](#message-records) per request, response or failure, in order. Absent when nothing was sent |
| `result` | object | The [result](#results) of the command. Present on success and with some failures |
| `error` | object | The [error](#errors) when `ok` is `false` |
| `warnings` | array of strings | Problems that did not fail the command, such as a CRL signature that does not verify |

An enrollment produces a document like this, shortened:

```json
{
  "command": "enroll",
  "ok": true,
  "exitStatus": 0,
  "server": "https://ca.example.com/.well-known/cmp",
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

### Message records

| Field | Meaning |
|---|---|
| `kind` | `request`, `response` or `failure`. A failure is a request that got no HTTP response |
| `time` | When the request was sent or the response or failure arrived |
| `elapsedMs` | Round-trip time of a response or failure in milliseconds |
| `httpStatus`, `contentType` | The HTTP status and content type of a response |
| `size` | Body size in bytes |
| `body` | The PKIBody type, such as `ir`, `ip`, `genp` or `error`. Absent when the body is not a CMP message |
| `protection` | The protection algorithm, such as `PBMAC1` or `ML-DSA-65`. It is `none` for an unprotected message |
| `sender` | The sender name in the header |
| `transactionId`, `senderKid` | Header fields, as hex |
| `status`, `failInfo`, `statusText` | The first PKIStatusInfo of an `ip`, `cp`, `kup`, `rp` or `error` body. `failInfo` lists the failure bit names |
| `checkAfter` | The seconds a `pollRep` asks the client to wait |
| `extraCerts` | The number of certificates in `extraCerts` |
| `problem` | Why a response cannot be a CMP answer (for example `HTTP 404 Not Found`) or why a request failed |
| `der` | The message bytes. Only capture files include them |

### Errors

| Field | Meaning |
|---|---|
| `title` | One line that says what failed, as in the text report |
| `message` | The underlying error |
| `status`, `failInfo`, `statusText` | The CA status of a rejection |
| `unauthenticated` | `true` when certrally could not verify the rejection, so any peer on the path could have sent it |
| `hint` | What to check or change, when certrally can tell |
| `note` | More context, such as advice for an issued but unconfirmed certificate |

### Results

A certificate in a result has `subject`, `issuer`, `serial`, `notBefore`, `notAfter`, `altNames`, `key`, `sha256` and `pem`.

| Command | Result fields |
|---|---|
| `enroll` | `status`, `confirmed`, `certificate`, `chain`, `saved`. With exit status 5 the result is present and `confirmed` is `false` |
| `revoke` | `certificate`, `reason` |
| `cacerts`, `cmp genm cacerts` | `certificates`, `saved` |
| `cmp genm rootupdate` | `update` with `newWithNew`, `newWithOld` and `oldWithNew`. It is `null` when no update is available. `saved` |
| `cmp genm template` | `template` with `subject`, `extensions` and `keyTypes`. It is `null` when the CA imposes nothing. An attribute without a value in `subject` is one the requester fills in. Each extension has `oid`, `name` and `critical` |
| `cmp genm crl`, `cmp genm crlupdate` | `crl` with `issuer`, `thisUpdate`, `nextUpdate`, `number`, `revoked`, `signature` and `pem`. It is `null` when there is none. `signature` is `valid`, `invalid` or `unchecked`. `saved` |
| `cmp genm raw` | `items`, each with `infoType`, `oid` and `value` |
| `ping` | `sent`, `answered`, `sender`, `protection`, `rttMs` with `min`, `avg` and `max`. With `--ca-cert`, `verified` tells whether every answer was signed by that CA |
| `keygen` | `keyType`, `key`, `publicKey`, `csr`, `saved`. With `--list`, `keyTypes` |

`saved` lists the files written, in the order they were written.

## Capture files

`--capture FILE` works with every command that talks to a server. It appends the run to `FILE` as JSON Lines, one JSON object per line:

1. A `start` line with `format` (currently 1), `tool`, `version`, `command`, `server` and `time`.
2. One [message record](#message-records) per request, response or failure, including `der`.
3. An `end` line with `time` and `exitStatus`.

Each run appends its own lines, so one file can hold several runs. `--capture` works together with `--json` and `--quiet`.

certrally creates the file with mode 0600. Keep capture files private: anyone who has the messages of a MAC-protected exchange can try to guess the shared secret offline.
