# certrally

certrally is a command line client for certificate enrollment with the Certificate Management Protocol (CMP, RFC 9810).

> [!NOTE]
> certrally is in early development. It has no enrollment commands yet.

Planned for the first releases:

* Enrollment, key update and revocation over CMP (`ir`, `cr`, `kur`, `p10cr`, `rr`) and the RFC 9483 support messages
* ML-DSA and composite ML-DSA keys alongside RSA, ECDSA and Ed25519
* A live view of every message in a transaction, with decoded messages and clear error explanations
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
certrally --version
```

`certrally completion bash|zsh|fish|powershell` prints a shell completion script. `certrally man` prints a man page.

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

certrally exits with status 0 on success and 1 on any error, including an invalid command line.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues as described in [SECURITY.md](SECURITY.md).

## License

certrally is licensed under the [Apache License 2.0](LICENSE).
