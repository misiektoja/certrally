# What this changes

<!-- What the change does and why. Link the issue it closes. -->

## Validation

<!-- Which of these you ran, and anything that failed. -->

- [ ] `make test`
- [ ] `make lint`
- [ ] `make actionlint`, for a workflow change
- [ ] `make release-config-check` and `make release-snapshot`, for a release or packaging change
- [ ] `make demo`, when the output of `enroll` or `revoke` changes
- [ ] Exercised against a real CMP, EST or SCEP server, for a protocol change

<!-- Name the server and its version, without hostnames or credentials. -->

## Documentation and release notes

- [ ] User-facing behavior is documented in the README, the command help or `docs/`
- [ ] `RELEASE_NOTES.md` carries an entry, or the change is not user facing
- [ ] A protocol change cites the RFC section and has a negative test

## Anything a reviewer should know

<!-- Trade-offs, follow-up work, or parts you are unsure about. -->

<!-- Never include shared secrets, passwords, private keys, capture files from a production system or
     production endpoint details in a pull request. -->
