# Keys and output files

These options work the same for the CMP and EST commands.

## Key files

certrally writes private keys as unencrypted PKCS#8 PEM with mode 0600. `certrally keygen --list` prints the key types.

`--key` and `--new-key` also take an encrypted PKCS#8 key, as `openssl pkcs8 -topk8` writes it (PBES2 with PBKDF2 and AES). The password comes from `--key-password-file` (`-` reads standard input), the `CERTRALLY_KEY_PASSWORD` environment variable or a prompt on a terminal, in that order. A key encrypted the older way, with `Proc-Type` headers in the PEM file, is not supported. This command converts one:

```bash
openssl pkcs8 -topk8 -in old.key -out device.p8
```

## Generate a key offline

`keygen` creates a key without contacting a CA, for example to send a PKCS#10 request through another channel:

```bash
certrally keygen --key-type ml-dsa-65 --out device.key \
  --csr-out device.csr --subject CN=device-42 --san device-42.example.com
```

`--pub-out` also saves the public key. An ML-KEM key cannot sign a request, so `--csr-out` does not work with `--key-type ml-kem-768` or `ml-kem-1024`.

## DER output

`--out-format der` writes the output files as DER instead of PEM. A certificate, a PKCS#8 key, a public key, a request and a CRL are written as is. A file that holds several certificates, such as `--chain-out` and the `--out` of `cacerts` and `est cacerts`, becomes PKCS#7. `poll` keeps the format of the `enroll` run unless its own `--out-format` replaces it. The default is `pem`.
