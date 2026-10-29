# SCEP details

The [README](../README.md#enroll-over-scep) introduces the `certrally scep` commands. This page covers how they trust the CA, the challenge password, algorithms, pending requests, renewal, queries and the `scep mock` test CA. Key files, encrypted keys and `--out-format der` work as for CMP, see [keys.md](keys.md).

## Server address and CA name

`--server` is the SCEP URL of the server, such as `http://scep.example.com/scep`. certrally adds the `operation` and `message` query parameters of RFC 8894 section 4.1.

A server that serves several CAs needs the name of the CA in `--ca`, which certrally sends as the `message` parameter of GetCACert, GetCACertChain, GetNextCACert and GetCACaps. Some servers answer GetCACert without content when the name is missing or unknown. certrally then exits with status 2 and suggests `--ca`. A `404 Not Found` usually means a wrong path in `--server`, but some servers also answer it for a CA name they do not serve.

## Trusting the CA

SCEP signs and encrypts its messages itself, so it often runs over plain HTTP. Nothing then authenticates the first GetCACert answer. Commands without `--ca-cert` trust the certificates of that answer and warn about it.

Check the CA once and save it for later commands:

```bash
certrally scep cacert --server http://scep.example.com/scep --ca 'Issuing CA'
certrally scep cacert --server http://scep.example.com/scep --ca 'Issuing CA' \
  --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --out ca.pem
```

`scep cacert` shows each certificate with its SHA-256 and SHA-1 fingerprints and its role: the issuing CA, an RA that decrypts requests or an RA that signs answers. `--fingerprint` takes a SHA-256 or SHA-1 fingerprint in hex, with or without colons. The certificate with that fingerprint is saved together with the certificates it issued, such as RA certificates. The other certificates of the answer are listed and not saved. Later commands trust the saved file with `--ca-cert` and do not send GetCACert. `--fingerprint` on the other commands checks the GetCACert answer before the request is sent.

`scep chain` sends GetCACertChain, which RFC 8894 does not define but some servers offer. It shows the CA certificate followed by the certificates that issued it, in the order of the server. `--fingerprint` and `--out` work as for `scep cacert`, so the fingerprint of the root saves the whole chain.

Over HTTPS the server certificate is checked against the system roots or `--tls-ca-cert`. `--insecure` skips that check for a test server.

## Challenge password

A PKCSReq carries a challenge password that authorizes the request. It comes from `--challenge`, `--challenge-file` (`-` reads standard input) or the `CERTRALLY_CHALLENGE` environment variable, in that order. certrally never asks for it, because many servers need none. Other users of the machine can see `--challenge` in the process list. Some servers also check the challenge password in a RenewalReq, so `scep renew` accepts the same flags.

Some servers refuse a missing or wrong challenge password with an HTTP error such as `400 Bad Request` or `403 Forbidden` instead of a FAILURE answer. Some do the same for a subject they do not know. certrally exits with status 3, shows the text of the error page and suggests checking the challenge password, `--subject` and `--ca`.

## Algorithms

Before a PKIOperation certrally sends GetCACaps and picks the algorithms from the answer:

| Choice | Default | Flag |
|---|---|---|
| Signature digest | SHA-256, or SHA-512 or SHA-1 when the server lists one of them and not SHA-256 | `--hash`: `sha256`, `sha384`, `sha512`, `sha1` or `md5` |
| Content cipher | AES-128-CBC, or DES-EDE3-CBC when the server lists DES3 and not AES | `--cipher`: `aes128`, `aes192`, `aes256`, `des3` or `des` |
| HTTP method | POST when the server lists POSTPKIOperation, GET otherwise | |

A server that lists SCEPStandard gets SHA-256, AES-128-CBC and POST. `scep caps` shows the capabilities and these choices.

certrally signs a PKCSReq with a self-signed certificate for the request key, or for a temporary RSA key when the request key is not RSA, because SCEP encrypts answers to the signer key. The transaction ID is the SHA-1 hash of the public key in uppercase hex, so a request for the same key always has the same ID.

certrally decrypts answers encrypted with AES or DES-EDE3-CBC and always with the cipher of its request. Some servers encrypt their answers with single DES whatever the request used. certrally then exits with status 4 and suggests `--allow-des`, which accepts them. Single DES offers no real protection for the certificate, but the certificate is public.

## Waiting for the CA

A CA that an operator must approve answers PENDING. `scep enroll` and `scep renew` then send CertPoll every `--poll-interval` (default 30 seconds) until the CA issues or rejects the certificate, within `--timeout` (default 5 minutes). `--poll-later` stops at the first PENDING answer. Some servers send a PENDING answer with HTTP `202 Accepted` and a FAILURE answer with `400 Bad Request`. certrally reads the CertRep whatever the HTTP status.

A request that is still pending is saved in a state file, by default the `--cert-out` file name with `.state` appended, or the file in `--state`. It holds the request, the certificate that signs it, the temporary signer key when there is one, the CA certificates and the output file names. It never holds the challenge password. It is written with mode 0600 and removed once the CA decides. At the end of `--timeout`, certrally keeps the state file and exits with status 2.

```bash
certrally scep poll --state device.pem.state
```

`scep poll` continues the request from the state file and saves the certificate where the enrollment would have. `--once` sends a single CertPoll. `--server`, `--ca` and `--allow-des` replace the values of the state file.

## Renewal

`scep renew` sends a RenewalReq signed with the certificate in `--cert` and its key in `--key`, which must be RSA. The request repeats the subject and subjectAltName of the certificate. A new key is generated unless `--new-key` or `--csr` supplies one. The server must list Renewal in its capabilities. certrally warns when it does not. Some servers list Renewal and still answer a RenewalReq with FAILURE and `badCertId`. They may expect a PKCSReq signed with the current certificate instead, which certrally does not send.

## Certificates and CRLs from the CA

`scep getcert --serial` gets a certificate the CA issued, by its serial number in decimal, `0x` hex or colon-separated hex. The issuer is the CA certificate unless `--issuer` names another. `scep getcrl` gets the CRL for the certificate in `--cert` or for `--serial` and checks its signature against the CA certificate.

Both requests are signed with `--cert` and `--key`, which servers usually require to be a certificate the CA issued, or else with a temporary self-signed certificate. Some servers answer these message types or RenewalReq without content when they do not support them. certrally then exits with status 2 and says so.

`scep nextca` sends GetNextCACert and shows the CA and RA certificates that will replace the current ones. The answer must be signed by the current CA or RA. Many servers have no next CA certificate, or answer without content when they lack the operation.

## Busy servers

A server under load may answer HTTP 503. certrally sends the request again up to `--busy-retries` times (default 3, `0` for never), after the time in the `Retry-After` header or after `--busy-wait` (default 5 seconds) when the header is missing.

## Proxies

`--proxy` takes an `http`, `https` or `socks5` URL. Without it, the `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables apply as for [CMP](cmp.md#trust-and-connections).

## Test CA

`certrally scep mock` runs a SCEP test CA on `127.0.0.1:8090` and prints commands that work against it. It answers GetCACaps, GetCACert, GetCACertChain and PKIOperation with PKCSReq, RenewalReq, CertPoll, GetCert and GetCRL over plain HTTP. Everything it issues lives in memory.

| Flag | Effect |
|---|---|
| `--challenge`, `--challenge-file` | The challenge password a PKCSReq must carry. Without them and `CERTRALLY_CHALLENGE`, a random one is generated and printed |
| `--any-challenge` | Issues whatever challenge password a request carries |
| `--ca-name` | Answers GetCACert only for this CA name |
| `--ra` | Decrypts requests and signs answers with a separate RA certificate |
| `--next-ca` | Announces a next CA certificate through GetNextCACert |
| `--pending-polls N` | Answers every new request with PENDING and issues the certificate at the Nth CertPoll |
| `--busy-interval` | Answers HTTP 503 without `Retry-After` to a PKIOperation sent within this time of the previous one |
| `--caps` | Replaces the GetCACaps answer, such as `SHA-1,DES3` for an old CA |
| `--ca-out` | Saves the GetCACert certificates for `--ca-cert` |

The mock prints a line for each request with the operation, the message type, the answer and the reason for a refusal.
