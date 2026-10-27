# Getting help

Start with the [README](README.md). It covers installation, the main commands, the trust model and the [exit statuses](README.md#exit-status). Its [documentation list](README.md#documentation) links the pages that describe the other options. [docs/json.md](docs/json.md) describes the `--json` output, [docs/profiles.md](docs/profiles.md) the RFC 9483 and RFC 7030 rules certrally checks and [docs/interop.md](docs/interop.md) how the tested CA servers behave.

## Check first

Most problems come from settings that differ between CA servers. Before asking, confirm that:

* `certrally ping` reaches the server and gets a CMP answer. For EST, `certrally est cacerts` gets the CA certificates.
* The hint under the message diagram names a flag. Most failures say which one to check, such as `--ref`, `--ca-cert` or `--tls-ca-cert`.
* The shared secret and the reference in `--ref` are the ones the CA expects. A CA that accepts only PasswordBasedMac needs `--mac pbm`.
* A response that breaks a profile rule is accepted with a warning by `--profile compatible`, the default. `--profile strict` stops at it with exit status 6.
* `--capture run.jsonl` records the exchange and `certrally inspect run.jsonl` decodes it, so you can see what the server sent.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question | [Question](https://github.com/misiektoja/certrally/issues/new?template=question.yml) |
| Report something broken | [Bug report](https://github.com/misiektoja/certrally/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/certrally/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/certrally/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the output of `certrally --version`, how you installed certrally, your operating system, the CA or EST server and its version and the command you ran with hostnames and credentials removed. Attach the message diagram and the error certrally printed, or the document from `--json`.

Never post shared secrets, passwords, private keys, capture files from a production system or production endpoint details. A capture of a shared-secret exchange allows offline guessing of the secret. See [SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so reproduce the problem on the current version before reporting it.
