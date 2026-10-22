# EST details

The [README](../README.md#enroll-over-est) introduces the `certrally est` commands and how they sign in.

## Waiting for the CA

When the server answers that a request is pending, `est enroll`, `est reenroll` and `est serverkeygen` wait as its `Retry-After` header asks and send the request again, within `--timeout` (default 5 minutes).

## Channel binding

`--tls-unique` binds the request to the TLS session (RFC 7030 section 3.5), which works only over TLS 1.2.

## Server-generated keys

`est serverkeygen` saves an unencrypted server key like other keys, as PKCS#8 PEM with mode 0600. It cannot decrypt a key the server encrypts.

## Test CA

`certrally est mock` runs an EST test CA on `127.0.0.1:8443` and prints commands that work against it. It accepts the password of `--user` (default `demo`) and certificates it issued. `--srp-listen 127.0.0.1:8444` also serves TLS-SRP for the same user. `--retry-after` answers the first request for each key with `202 Accepted`, to test waiting. It generates a password unless `--password-file` or `CERTRALLY_PASSWORD` gives one.
