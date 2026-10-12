# Release Notes

Notable changes to certrally. Versions follow the `vMAJOR.MINOR.PATCH` tags published in this repository.

## v0.1.0 - TBD

The first version sets up the `certrally` command. It has no enrollment commands yet.

### Command line

* **`certrally --help`** describes the command and its flags. **`--version`** prints the version recorded at build time. **`certrally completion`** prints shell completion scripts for bash, zsh, fish and PowerShell. **`certrally man`** prints a man page.
* **`--color auto|always|never`** controls coloured output. `auto`, the default, colours output only on a terminal. `NO_COLOR` with any non-empty value turns colour off. `FORCE_COLOR` and `CLICOLOR_FORCE` turn it on for pipes and files. `--color` overrides all of them.
* certrally exits with status 1 on any error, including an invalid command line.
