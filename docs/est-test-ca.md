# EST test CA

`certrally est mock` runs an EST test CA on your machine, for trying certrally and test scripts without a real EST server. Start it in one terminal:

```bash
certrally est mock --password demo-password --ca-out ca.pem
```

Request a certificate from another terminal in the same directory:

```bash
certrally est enroll --server https://127.0.0.1:8443 --tls-ca-cert ca.pem --user demo --password demo-password --subject CN=device --cert-out device.pem --key-out device.key
```

The test CA prints the same command when it starts. It listens on `127.0.0.1:8443` (`--listen`). It accepts the password of `--user` (default `demo`) and certificates it issued. `--srp-listen 127.0.0.1:8444` also serves TLS-SRP for the same user. `--retry-after` answers the first request for each key with `202 Accepted`, to test waiting. It generates a password unless `--password`, `--password-file` or `CERTRALLY_PASSWORD` gives one. The printed commands give the password with `--password` and the token with `--token`, name the files of `--password-file` and `--token-file` and leave out values from the environment. With `--token`, `--token-file` or `CERTRALLY_TOKEN` it also accepts that bearer token with `est enroll --token`. The CA key and everything it issued live in memory and are lost when it stops.

[Using EST](est.md) describes the EST commands.
