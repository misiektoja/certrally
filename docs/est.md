# EST details

The [README](../README.md#enroll-over-est) introduces the `certrally est` commands. This page covers how they sign in and the less common options. Key files, encrypted keys and `--out-format der` work as for CMP, see [keys.md](keys.md).

## Signing in

* **A password** over HTTP Basic authentication with `--user`. The password comes from `--password`, `--password-file` (`-` reads standard input), the `CERTRALLY_PASSWORD` environment variable or a prompt on a terminal, in that order.
* **A bearer token** over HTTP Bearer authentication (RFC 6750) with `--token`. The token comes from `--token=TOKEN`, `--token-file` (`-` reads standard input, which implies `--token`), the `CERTRALLY_TOKEN` environment variable or a prompt on a terminal, in that order. A token on the command line needs the `=`, because `--token` alone only selects the sign-in. `--token` cannot be combined with `--user`.
* **A TLS client certificate** with `--cert` and `--key`. `est reenroll --cert device.pem --key device.key` renews a certificate this way. Without `--key`, renewal signs in with `--user` or `--token` instead, as RFC 7030 section 2.3 allows for certificates that cannot be used for TLS.
* **TLS-SRP** with `--srp` and `--user`. The password then authenticates both sides over TLS 1.2, so the server needs no certificate and `--srp` cannot be combined with `--tls-ca-cert`.

Other users of the machine can see `--password` and `--token=TOKEN` in the process list, and the shell may keep them in its history.

## Server certificate and bootstrap

The server certificate is checked against the system roots or against the CA certificates in `--tls-ca-cert`. `--insecure` skips that check for a test server and warns that anyone who intercepts the connection can pose as the server.

When nothing can check the certificate yet, `est cacerts --bootstrap` connects without the check (RFC 7030 section 4.1.1). It saves the certificate whose fingerprint matches `--fingerprint` or the one a person confirms on a terminal, together with the certificates it issued. The other certificates of the response are listed with a note and not saved:

```bash
certrally est cacerts --server https://est.example.com --bootstrap \
  --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --out ca.pem
```

`--bootstrap` cannot be combined with `--user`, `--password`, `--password-file`, `--token` or `--token-file`. The request needs no sign-in and the credentials would reach a server that nothing checked.

## Proxies

`--proxy` and the `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` environment variables work as for [CMP](cmp.md#trust-and-connections). The EST commands tunnel through the proxy with CONNECT, so TLS-SRP and `--tls-unique` work through it.

## Waiting for the CA

When the server answers that a request is pending, `est enroll`, `est reenroll` and `est serverkeygen` wait as its `Retry-After` header asks and send the request again, within `--timeout` (default 5 minutes).

## Channel binding

`--tls-unique` binds the request to the TLS session (RFC 7030 section 3.5), which works only over TLS 1.2.

## Server-generated keys

`est serverkeygen` saves an unencrypted server key like other keys, as PKCS#8 PEM with mode 0600. `--out-format der` saves it as PKCS#8 DER. It cannot decrypt a key the server encrypts.

## Test CA

`certrally est mock` runs an EST test CA on `127.0.0.1:8443` and prints commands that work against it. It accepts the password of `--user` (default `demo`) and certificates it issued. `--srp-listen 127.0.0.1:8444` also serves TLS-SRP for the same user. `--retry-after` answers the first request for each key with `202 Accepted`, to test waiting. It generates a password unless `--password`, `--password-file` or `CERTRALLY_PASSWORD` gives one. With `--token`, `--token-file` or `CERTRALLY_TOKEN` it also accepts that bearer token with `est enroll --token`.
