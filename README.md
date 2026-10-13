# certrally

certrally is a command line client for certificate enrollment with the Certificate Management Protocol (CMP, RFC 9810).

> [!NOTE]
> certrally is in early development. `certrally enroll` is the first command.

* Enrollment and key update over CMP (`ir`, `cr`, `kur`, `p10cr`) with a shared secret or a certificate
* ML-DSA and composite ML-DSA keys alongside RSA, ECDSA and Ed25519
* A live diagram of every message in the exchange and plain explanations of failures
* Exit statuses that tell scripts why a request failed

Planned for the first releases:

* Revocation (`rr`) and the RFC 9483 support messages
* Prebuilt binaries for Linux, macOS and Windows

EST support is planned after CMP.

## Install

certrally needs Go 1.27.2 or newer to build from source:

```bash
go install github.com/misiektoja/certrally/cmd/certrally@latest
```

## Usage

```bash
certrally --help
certrally enroll --help
certrally --version
```

`certrally completion bash|zsh|fish|powershell` prints a shell completion script. `certrally man` prints a man page.

### Enroll a certificate

A device that has a shared secret from its CA requests its first certificate with an initialization request (`ir`). `--ref` names the secret to the CA:

```bash
certrally enroll --server https://ca.example.com/.well-known/cmp \
  --ref device-42 --secret-file secret.txt \
  --subject CN=device-42,O=Example --san device-42.example.com \
  --trusted ca.pem --cert-out device.pem --key-out device.key
```

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
  --cert device.pem --key device.key --trusted ca.pem \
  --cert-out device-new.pem --key-out device-new.key
```

`--type cr` requests an additional certificate. `--type p10cr` sends a PKCS#10 request, either from `--csr` or built from `--subject` and `--san`.

Notes:

* The shared secret comes from `--secret-file` (`-` reads standard input), the `CERTRALLY_SECRET` environment variable or a prompt on a terminal, in that order. It is never accepted as a command line argument. One trailing line ending is removed.
* With a shared secret, the request header names `CN=<ref>` as the sender and `<ref>` as the key identifier, as RFC 9483 asks. Without `--subject` or `--san` the certificate is requested for `CN=<ref>`.
* `--trusted` names the CA certificate that responses and the issued certificate must chain to. It is required with `--cert`. Without it a shared-secret request trusts the CA certificate in the response on first use and cannot verify error messages.
* certrally generates an `ecdsa-p256` key unless `--key-type`, `--new-key` or `--csr` says otherwise. Key types are `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` and the composite ML-DSA combinations such as `mldsa65-ecdsa-p256-sha512`. Shell completion lists them all.
* Private keys are written as unencrypted PKCS#8 PEM with mode 0600. The key is written before the certificate. certrally refuses to replace an existing file unless `--force` is given, and checks this before sending anything.
* `--chain-out` saves the issuing CA certificates from the response, issuer first.
* `--timeout` (default 5 minutes) bounds the whole exchange, including polling while the CA prepares the certificate.

### Colour

certrally colours its output only when it writes to a terminal. These settings change that, highest priority first:

| Setting | Effect |
|---|---|
| `--color always` or `--color never` | Always or never use colour |
| `NO_COLOR` set to any non-empty value | No colour. Bold and other text styles remain on a terminal |
| `FORCE_COLOR` or `CLICOLOR_FORCE=1` | Colour even when the output is a pipe or a file. `FORCE_COLOR=0` and `FORCE_COLOR=false` have no effect |
| `TERM=dumb` | No colour |

The colour depth comes from `TERM` and `COLORTERM`.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid command line or local error, such as an unreadable file |
| 2 | The server could not be reached, did not answer in time or did not answer with CMP |
| 3 | The CA rejected the request |
| 4 | The response broke the protocol or failed verification |
| 5 | The CA issued the certificate but the confirmation failed. certrally saves the certificate. Check with the CA before retrying, because a retry can issue a second certificate |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

## License

certrally is licensed under the [Apache License 2.0](LICENSE).
