# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.1.0 - TBD

The first version requests certificates over CMP with **`certrally enroll`**, using a shared secret or an existing certificate, and shows each exchange as a live message diagram.

### Enrollment

* **`certrally enroll`** requests a certificate with an initialization (`ir`), certification (`cr`), key update (`kur`) or PKCS#10 (`p10cr`) request. It polls while the CA prepares the certificate, confirms it and saves it with `--cert-out`, the new key with `--key-out` and the issuing CA certificates with `--chain-out`.
* **Shared-secret protection** uses `--ref` and a secret from `--secret-file`, the `CERTRALLY_SECRET` environment variable or a prompt. The secret is never taken from the command line. PBMAC1 is the default and `--mac pbm` selects PasswordBasedMac. **Signature protection** uses `--cert` and `--key` and requires `--trusted`.
* **Key types** cover ECDSA P-256 (the default), P-384 and P-521, Ed25519, RSA 2048 to 4096, ML-DSA-44, ML-DSA-65 and ML-DSA-87 and the composite ML-DSA combinations. `--new-key` certifies an existing key and `--csr` sends an existing PKCS#10 request.
* `--subject` takes an RFC 4514 name and `--san` adds DNS names, IP addresses, email addresses and URIs. `--recipient`, `--sender` and `--cert-profile` set the matching request header fields.
* A **ladder diagram** on standard error shows every message with its protection, size, status and round-trip time. Failures are explained with the CA status, its failure reasons and a hint about which flag to check. `--quiet` hides the diagram and the summary.
* Private keys are saved as PKCS#8 PEM with mode 0600. Existing files are kept unless `--force` is given, and certrally checks this before it sends a request.
* **Exit statuses** separate failures: 1 for an invalid command line or local error, 2 when the server is unreachable or does not answer with CMP, 3 when the CA rejects the request, 4 for protocol or verification failures and 5 when the certificate was issued but the confirmation failed.

### Command line

* **`certrally --help`** describes the command and its flags. **`--version`** prints the version recorded at build time. **`certrally completion`** prints shell completion scripts for bash, zsh, fish and PowerShell. **`certrally man`** prints a man page.
* **`--color auto|always|never`** controls coloured output. `auto`, the default, colours output only on a terminal. `NO_COLOR` with any non-empty value turns colour off. `FORCE_COLOR` and `CLICOLOR_FORCE` turn it on for pipes and files. `--color` overrides all of them.
