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
| Enroll a first certificate over CMP, renew it and revoke it | [Getting started](getting-started.md) |
| Use the other CMP options and commands | [CMP details](cmp.md) |
| Enroll over EST | [Enroll over EST](est.md) |
| Enroll over SCEP | [Enroll over SCEP](scep.md) |
| Choose key types, encrypted keys or DER output | [Keys and output files](keys.md) |
| Run certrally from a script | [Scripts and exit status](scripts.md) |
| Check responses against the RFCs | [Response profiles](profiles.md) |
| Decode and check recorded messages | [Inspect and lint recorded messages](inspect.md) |
| Run a test CA on my machine | [The CMP test CA](mock.md), [EST](est.md#test-ca) and [SCEP](scep.md#test-ca) |
| Test how a CA copes with wrong messages | [Testing a CA with faulty messages](faults.md) |
| Find notes for my CA server | [Tested servers](interop.md) |
| Check a download | [Verify a download](verify.md) |
| Ask for help or report a problem | [Support](https://github.com/misiektoja/certrally/blob/main/SUPPORT.md) |
| Contribute | [Contributing](https://github.com/misiektoja/certrally/blob/main/CONTRIBUTING.md) |
