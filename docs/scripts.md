# Scripts and exit status

## JSON output

`--json` prints the outcome as one JSON document on standard output instead of the diagram and the report. The document holds the exit status, every message of the exchange, the result of the command and any error:

```bash
certrally cacerts --server https://ca.example.com/.well-known/cmp --ref device-42 --json \
  | jq -r '.result.certificates[].subject'
```

`--capture run.jsonl` appends every message of the run, with its bytes, to a JSON Lines file that [`inspect` and `lint`](inspect.md) read. Keep capture files private, because the messages of a shared-secret exchange allow offline guessing of the secret.

[JSON output and capture files](json.md) describes both formats.

## Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Invalid command line or local error, such as an unreadable file |
| 2 | The server could not be reached, did not answer in time or did not answer with CMP, EST or SCEP |
| 3 | The CA rejected the request, or the EST or SCEP server refused it or the sign-in |
| 4 | The response broke the protocol or failed verification |
| 5 | The CA issued the certificate but the confirmation failed. certrally saves the certificate. Check with the CA before retrying, because a retry can issue a second certificate |
| 6 | A response broke a rule of `--profile strict`, or `lint` found a response that breaks a rule |
