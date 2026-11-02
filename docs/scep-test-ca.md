# SCEP test CA

`certrally scep mock` runs a SCEP test CA on your machine, for trying certrally and test scripts without a real SCEP server. Start it in one terminal:

```bash
certrally scep mock --challenge demo-challenge --ca-out ca.pem
```

Request a certificate from another terminal in the same directory:

```bash
certrally scep enroll --server http://127.0.0.1:8090/scep --ca-cert ca.pem --challenge demo-challenge --subject CN=device --cert-out device.pem --key-out device.key
```

The test CA prints the same command when it starts. It listens on `127.0.0.1:8090` (`--listen`). The printed `scep enroll` command gives the challenge password with `--challenge`, names the file of `--challenge-file` and leaves out a challenge from `CERTRALLY_CHALLENGE`. It answers GetCACaps, GetCACert, GetCACertChain and PKIOperation with PKCSReq, RenewalReq, CertPoll, GetCert and GetCRL over plain HTTP. Everything it issues lives in memory.

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

The test CA prints a line for each request with the operation, the message type, the answer and the reason for a refusal.

[Using SCEP](scep.md) describes the SCEP commands.
