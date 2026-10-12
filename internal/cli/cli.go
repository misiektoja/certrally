// Package cli implements the certrally command line.
package cli

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/misiektoja/certrally/internal/termcolor"
)

// Run executes the command line in args and returns the process exit status.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	// Help and usage errors are rendered before any command hook runs, so the colour mode has to be
	// applied before cobra parses the command line.
	if err := termcolor.Apply(colorModeFromArgs(args)); err != nil {
		_, _ = fmt.Fprintln(stderr, "certrally:", err)
		return 1
	}

	root := newRootCommand()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	var opts []fang.Option
	if info, ok := debug.ReadBuildInfo(); ok {
		version, commit := buildVersion(info)
		if version != "" {
			opts = append(opts, fang.WithVersion(version), fang.WithCommit(commit))
		}
	}
	if err := fang.Execute(ctx, root, opts...); err != nil {
		return 1
	}
	return 0
}

// newRootCommand returns the certrally command with its global flags.
func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certrally",
		Short: "Certificate enrollment client for CMP",
		Long: "certrally is a certificate enrollment client for the Certificate Management Protocol (CMP).\n\n" +
			"It is in early development and has no enrollment commands yet.",
	}

	// Run applies the colour mode before parsing. The flag is still defined here so that help lists
	// it, an invalid value is rejected and shell completion offers the valid values.
	mode := colorFlag(termcolor.Auto)
	cmd.PersistentFlags().Var(&mode, "color", "when to colour output: auto, always or never")
	_ = cmd.RegisterFlagCompletionFunc("color", completeColorMode)
	return cmd
}

// completeColorMode offers the --color values to shell completion.
func completeColorMode(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	values := make([]string, len(termcolor.Modes))
	for i, m := range termcolor.Modes {
		values[i] = string(m)
	}
	return values, cobra.ShellCompDirectiveNoFileComp
}

// colorModeFromArgs returns the --color value in args, or Auto when it is absent or invalid. An
// invalid value is reported later by cobra, with the rest of the command line.
func colorModeFromArgs(args []string) termcolor.Mode {
	fs := pflag.NewFlagSet("certrally", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	// Without its own help flag, pflag stops at --help and ignores a --color that follows it.
	fs.BoolP("help", "h", false, "")
	mode := colorFlag(termcolor.Auto)
	fs.Var(&mode, "color", "")
	if err := fs.Parse(args); err != nil {
		return termcolor.Auto
	}
	return termcolor.Mode(mode)
}

// colorFlag is a pflag.Value that accepts only the termcolor modes.
type colorFlag termcolor.Mode

// String returns the current mode.
func (f *colorFlag) String() string { return string(*f) }

// Set validates and stores a mode.
func (f *colorFlag) Set(s string) error {
	m, err := termcolor.ParseMode(s)
	if err != nil {
		return err
	}
	*f = colorFlag(m)
	return nil
}

// Type names the value in help output.
func (f *colorFlag) Type() string { return "mode" }

// buildVersion returns the module version and VCS revision that Go stamped into the binary. The
// version is empty for a build without version information, which makes fang report it as unknown.
//
// fang reads build information only for binaries installed with go install. Go also stamps a version
// derived from the repository state into binaries built inside a Git checkout, and that version is
// worth showing.
func buildVersion(info *debug.BuildInfo) (version, commit string) {
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "", ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			commit = s.Value
		}
	}
	// A pseudo-version already ends in the first twelve characters of the revision.
	if len(commit) >= 12 && strings.Contains(info.Main.Version, commit[:12]) {
		commit = ""
	}
	return info.Main.Version, commit
}
