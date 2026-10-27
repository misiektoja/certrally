# Output and colour

The message diagram goes to standard error and the summary to standard output. `--quiet` hides both. `--json` replaces them with one JSON document, see [json.md](json.md).

## Colour

certrally colours its output only when it writes to a terminal. These settings change that, highest priority first:

| Setting | Effect |
|---|---|
| `--color always` or `--color never` | Always or never use colour |
| `NO_COLOR` set to any non-empty value | No colour. Bold and other text styles remain on a terminal |
| `FORCE_COLOR` or `CLICOLOR_FORCE=1` | Colour even when the output is a pipe or a file. `FORCE_COLOR=0` and `FORCE_COLOR=false` have no effect |
| `TERM=dumb` | No colour |

The colour depth comes from `TERM` and `COLORTERM`.

## Existing files

certrally does not replace an existing output file, such as `--cert-out` or `--key-out`, unless `--force` is given. On a terminal it asks first, once for all the files that exist, and the default answer is no. Without a terminal, and with `--json`, it stops with an error instead. The check runs before anything is sent, so a refusal costs no request.
