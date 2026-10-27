# Inspect and lint recorded messages

`--capture FILE` records every message of a run. [json.md](json.md#capture-files) describes the format. Keep capture files private, because the messages of a shared-secret exchange allow offline guessing of the secret.

## inspect

`inspect` decodes the messages in a capture file or in files that hold a message as DER, base64 or hex or several as PEM blocks. It shows the header, the protection, the body and the extra certificates of each CMP message:

```bash
certrally inspect run.jsonl --ca-cert ca.pem
```

```text
← kup  run.jsonl:3  ECDSA SHA-256  1062 bytes  2026-10-13 11:02:04 UTC
  Header
    Version          2
    Sender           CN=Example CA
    Recipient        CN=device-42
    Message time     2026-10-13 11:02:04 UTC
    Transaction ID   C0:F1:6D:53:1F:6D:D3:FE:45:E3:D6:E2:2C:BD:DD:8E
    Sender nonce     8B:CD:7D:93:2E:99:E3:0A:91:3B:00:0E:BB:C0:D6:5D
    Recipient nonce  14:09:0A:43:F8:0F:2D:22:A5:74:49:BA:32:61:48:71
    Sender KID       3C:9F:DD:E9:90:36:2B:9D:3B:B9:8E:9F:A1:FB:C5:E4:2C:DF:B1:89
    General info     confirmWaitTime
  Protection
    Algorithm  ECDSA SHA-256
    Signature  valid
    Signer     CN=Example CA
    Trust      chains to --ca-cert
  Certificate response 0
    Status   accepted
    Subject  CN=device-42
    Issuer   CN=Example CA
    Serial   BB:CB:71:D5:56:10:E4:A2:CC:BD:89:CA:90:CC:B9:51
    Valid    2026-10-13 11:01 UTC to 2027-10-13 11:02 UTC
    Key      ECDSA P-256
  Extra certificate 1 (signer)
    Subject  CN=Example CA
    ...
```

For EST it shows the HTTP exchange from a capture and the PKCS#10 request, the certificates or the CSR attributes. It also reads PKCS#10 requests, PKCS#7 certificate files and CSR attributes saved as files.

certrally checks a signature with the certificates in the message and in `--ca-cert`, even when the signer certificate has expired. When `senderKID` names none of them, a certificate that verifies the signature still counts as the signer. With `--ca-cert` it also checks that the signer chains to those certificates. It checks the chain at the time the capture recorded the message. For other files it uses the current time. It checks a MAC with the shared secret from `--secret`, `--secret-file` or `CERTRALLY_SECRET` and leaves it unchecked without one.

## lint

`lint` checks recorded responses against the [profile rules](profiles.md) and exits with status 6 when a response breaks one. It reads the same files as `inspect`, but checks EST responses only in capture files, because the rules concern the HTTP response:

```bash
certrally lint run.jsonl
```

A FILE of `-` reads standard input.
