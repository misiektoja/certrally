package cli

import (
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// shellSafe matches the words a POSIX shell takes literally.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// shellQuote quotes s for a POSIX shell when it contains other characters.
func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// commandLine returns the command line that repeats the flags set on cmd, quoted for a POSIX shell.
// The flags in first come first and the others follow in name order. The flags in skip are left out.
func commandLine(cmd *cobra.Command, first []string, skip ...string) string {
	args := []string{cmd.CommandPath()}
	done := make(map[string]bool, len(skip))
	for _, name := range skip {
		done[name] = true
	}
	add := func(f *pflag.Flag) {
		if f == nil || !f.Changed || done[f.Name] {
			return
		}
		done[f.Name] = true
		switch v := f.Value.(type) {
		case pflag.SliceValue:
			for _, item := range v.GetSlice() {
				args = append(args, "--"+f.Name, shellQuote(item))
			}
		default:
			switch {
			case f.Value.Type() != "bool":
				args = append(args, "--"+f.Name, shellQuote(f.Value.String()))
			case f.Value.String() == "true":
				args = append(args, "--"+f.Name)
			default:
				args = append(args, "--"+f.Name+"=false")
			}
		}
	}
	for _, name := range first {
		add(cmd.Flags().Lookup(name))
	}
	cmd.Flags().VisitAll(add)
	return strings.Join(args, " ")
}
