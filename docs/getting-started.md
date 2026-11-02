# Getting started

This page enrolls a first certificate over CMP, renews it and revokes it. [Enroll over EST](est.md) and [Enroll over SCEP](scep.md) start the same way for the other protocols.

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

The test CA prints the same command when it starts. Without a secret it generates one and puts it in that command. Running `certrally enroll` without flags asks for every setting instead. The test CA keeps everything in memory, so every run starts empty. Its fault flags make it delay, reject or relax its checks, to test how a client copes. [The CMP test CA](mock.md) describes them.

## Enroll a certificate

With a real CA, a device that has a shared secret from the CA requests its first certificate with an initialization request (`ir`). `--ref` names the secret to the CA:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt \
  --subject CN=device-42,O=Example --san device-42.example.com \
  --cert-out device.pem --key-out device.key
```

`--secret VALUE` gives the secret on the command line instead, and `CERTRALLY_SECRET` or a prompt also work. [CMP details](cmp.md#protection) lists the order and the risk of `--secret`.

certrally draws each message as it is sent and received, then describes the certificate:

```text
  certrally                                           ca.example.com
  │                                                                │
  │ ir  PBMAC1  506 B                                              │
  │ ─────────────────────────────────────────────────────────────▶ │
  │                            ip  accepted  PBMAC1  1.5 KiB  9 ms │
  │ ◀───────────────────────────────────────────────────────────── │
  │ certConf  PBMAC1  291 B                                        │
  │ ─────────────────────────────────────────────────────────────▶ │
  │                                   pkiconf  PBMAC1  637 B  2 ms │
  │ ◀───────────────────────────────────────────────────────────── │

✓ Certificate issued
  Subject    CN=device-42,O=Example
  Alt names  device-42.example.com
  Issuer     CN=Example CA
  Serial     94:01:1D:E4:EA:C9:F1:25:59:06:0B:13:86:06:94:7D
  Valid      2026-10-13 00:20 UTC to 2027-10-13 00:21 UTC
  Key        ECDSA P-256
  Status     accepted
  Saved      device.key, device.pem
```

The diagram goes to standard error and the certificate summary to standard output. `--quiet` hides both.

A certificate the device already has signs later requests. A key update (`kur`) replaces the certificate in `--cert` with one for a new key:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp --type kur \
  --cert device.pem --key device.key \
  --cert-out device-new.pem --key-out device-new.key
```

`--type cr` requests an additional certificate. `--type p10cr` sends a PKCS#10 request, either from `--csr` or built from `--subject` and `--san`. Some CAs accept only PasswordBasedMac and need `--mac pbm`.

[CMP details](cmp.md) covers the other options: key usages and templates, implicit confirmation, collecting a waiting certificate later, ML-KEM keys, keys that the CA generates, forwarding as a registration authority, CA information requests and `ping`. [Keys and output files](keys.md) covers key types, encrypted keys and DER output.

## Enroll step by step

On a terminal, `certrally enroll` without flags asks for each setting: the server, the CA to trust, the shared secret or certificate, the names, the key type and the files to write. Flags you give answer their questions. `--interactive` asks only for the rest:

```bash
certrally enroll --interactive --server https://ca.example.com/.well-known/cmp
```

Before it sends the request, certrally prints the same request as one command for scripts and asks for confirmation. The shared secret is hidden while you type it. It never appears in that command, and neither do the values of `--secret` and `--key-password`. The questions cannot be combined with `--json`. With `ACCESSIBLE=1` they are asked line by line, for example for a screen reader.

## Revoke a certificate

RFC 9483 signs a revocation request with the certificate being revoked:

```bash
certrally revoke --server https://ca.example.com/.well-known/cmp \
  --cert device.pem --key device.key --reason keyCompromise
```

`--reason` takes an RFC 5280 reason name and defaults to `unspecified`. `certificateHold` suspends a certificate and `removeFromCRL` releases it, if the CA supports holds. An authority that revokes for someone else names the certificate with `--revoke-cert` or with `--serial` and `--issuer` as described in [CMP details](cmp.md#revoke-by-serial-number). On a terminal certrally asks before it sends the request. `--yes` skips the question.

## Trust the CA

certrally needs no trust setup. It trusts the CA certificates in the first response from the server and lists them with their SHA-256 fingerprints, so you can compare them with the ones the CA published. To make sure you talk to a particular CA, name its certificate with `--ca-cert ca.pem`. certrally then trusts nothing the server sends.

Over HTTPS the server is checked against the system roots or `--tls-ca-cert`. Over plain HTTP nothing authenticates the first response, so use `--ca-cert` there unless you trust the network. [CMP details](cmp.md#trust-and-connections) covers `--chain-out`, `--insecure` and proxies.

## Check responses against the RFCs

certrally warns when a response breaks a rule of RFC 9483, RFC 9810, RFC 7030 or RFC 8894 that some CAs do not follow. `--profile strict` rejects such responses instead and exits with status 6. [Response profiles](profiles.md) lists the rules. [Tested servers](interop.md) describes how tested CAs behave.
