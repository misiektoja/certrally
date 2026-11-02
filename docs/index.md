# certrally

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/certrally?style=flat-square&color=blue)](https://github.com/misiektoja/certrally/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/misiektoja/certrally/blob/main/LICENSE)
[![Tests](https://github.com/misiektoja/certrally/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/certrally/actions/workflows/test.yml)
[![Supply chain](https://github.com/misiektoja/certrally/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/certrally/actions/workflows/supply-chain.yml)

certrally is a command line client for certificate enrollment with the Certificate Management Protocol (CMP), Enrollment over Secure Transport (EST) and the Simple Certificate Enrolment Protocol (SCEP). It is free software under the Apache License 2.0.

![certrally enrolls an ML-DSA-65 certificate from the test CA with a shared secret](demo.gif)

--8<-- "README.md:features"

Tested with EJBCA, Nokia NCM, Insta Certifier and the `openssl cmp` mock server over CMP, with Cisco libest over EST and with EJBCA, Nokia NCM, OpenXPKI and micromdm/scep over SCEP. [Tested servers](interop.md) lists how each one behaves.

## Where to go next

| I want to | Page |
| --- | --- |
| Install certrally | [Install](install.md) |
| Pick a protocol and try a test CA | [Getting started](getting-started.md) |
| Enroll, renew and revoke over CMP | [Using CMP](cmp.md) |
| Enroll and renew over EST | [Using EST](est.md) |
| Enroll and renew over SCEP | [Using SCEP](scep.md) |
| Choose key types, encrypted keys or DER output | [Keys and output files](keys.md) |
| Run certrally from a script | [Scripts and exit status](scripts.md) |
| Check responses against the RFCs | [RFC checks](rfc-checks.md) |
| Decode and check recorded messages | [Inspect and lint recorded messages](inspect.md) |
| Run a test CA on my machine | [CMP test CA](cmp-test-ca.md), [EST test CA](est-test-ca.md) and [SCEP test CA](scep-test-ca.md) |
| Test how a CA copes with wrong messages | [Testing a CA with faulty messages](cmp-faults.md) |
| Find notes for my CA server | [Tested servers](interop.md) |
| Check a download | [Verify a download](verify.md) |
| Ask for help or report a problem | [Support](https://github.com/misiektoja/certrally/blob/main/SUPPORT.md) |
| Contribute | [Contributing](https://github.com/misiektoja/certrally/blob/main/CONTRIBUTING.md) |
