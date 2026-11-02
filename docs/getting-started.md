# Getting started

certrally enrolls certificates over three protocols. Use the one your CA offers:

| Protocol | How a client signs in | Guide |
|---|---|---|
| CMP | A shared secret or a certificate protects every message, over HTTP or HTTPS | [Using CMP](cmp.md) |
| EST | HTTPS with a password, a bearer token, a TLS client certificate or TLS-SRP | [Using EST](est.md) |
| SCEP | A challenge password in an encrypted request, usually over plain HTTP | [Using SCEP](scep.md) |

## Commands and help

--8<-- "README.md:usage"

Output is coloured only on a terminal. [Output and colour](output.md) describes `--color`, `NO_COLOR`, `FORCE_COLOR` and the handling of existing output files.

## Try it with a test CA

`certrally mock` runs a CMP test CA on your machine. Start it in one terminal:

```bash
certrally mock --secret demo-secret --ca-out ca.pem
```

Request a certificate from another terminal in the same directory:

```bash
certrally enroll --server http://127.0.0.1:8080/.well-known/cmp --ref demo --ca-cert ca.pem --secret demo-secret --cert-out device.pem --key-out device.key
```

The test CA prints the same command when it starts. Without a secret it generates one and puts it in that command. Running `certrally enroll` without flags [asks for every setting](cmp.md#enroll-step-by-step) instead. The test CA keeps everything in memory, so every run starts empty. Its fault flags make it delay, reject or relax its checks, to test how a client copes. [CMP test CA](cmp-test-ca.md) describes them. `certrally est mock` and `certrally scep mock` run test CAs for the other protocols, see [EST test CA](est-test-ca.md) and [SCEP test CA](scep-test-ca.md).

## Trust the CA

certrally needs no trust setup. It trusts the CA it talks to unless you name the CA certificate. How it decides depends on the protocol:

* CMP trusts the CA certificates in the first response and lists them with their SHA-256 fingerprints, so you can compare them with the ones the CA published. `--ca-cert` names the CA instead. See [Trust and connections](cmp.md#trust-and-connections).
* EST checks the HTTPS server against the system roots or `--tls-ca-cert`. `est cacerts --bootstrap` gets the first CA certificates after a fingerprint check. See [Server certificate and bootstrap](est.md#server-certificate-and-bootstrap).
* SCEP trusts the first GetCACert answer, which usually arrives over plain HTTP, and warns about it. `scep cacert --fingerprint` saves the CA certificates after a fingerprint check and `--ca-cert` names them later. See [Trusting the CA](scep.md#trusting-the-ca).

## Check responses against the RFCs

certrally warns when a response breaks a rule of RFC 9483, RFC 9810, RFC 7030 or RFC 8894 that some CAs do not follow. `--profile strict` rejects such responses instead and exits with status 6. [RFC checks](rfc-checks.md) lists the rules. [Tested servers](interop.md) describes how tested CAs behave.
