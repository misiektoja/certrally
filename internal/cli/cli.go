// Package cli implements the certrally command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strings"

	"charm.land/fang/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/misiektoja/certrally/internal/termcolor"
)

// programName is the name of the command and of the client in ladders and capture files.
const programName = "certrally"

// Run executes the command line in args and returns the process exit status.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	// Help and usage errors are rendered before any command hook runs, so the colour mode has to be
	// applied before cobra parses the command line.
	if err := termcolor.Apply(colorModeFromArgs(args)); err != nil {
		_, _ = fmt.Fprintln(stderr, "certrally:", err)
		return exitLocal
	}

	root := newRootCommand()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	opts := []fang.Option{fang.WithErrorHandler(handleError)}
	if info, ok := debug.ReadBuildInfo(); ok {
		version, commit := buildVersion(info)
		if version != "" {
			opts = append(opts, fang.WithVersion(version), fang.WithCommit(commit))
		}
	}
	if err := fang.Execute(ctx, root, opts...); err != nil {
		if ee, ok := errors.AsType[*exitError](err); ok {
			return ee.code
		}
		// cobra rejected the command line before the command ran. A script that asked for JSON
		// still gets its document. fang has already printed the error for a person.
		if jsonFromArgs(args) {
			writeUsageJSON(stdout, root, args, err)
		}
		return exitLocal
	}
	return exitOK
}

// writeUsageJSON writes the JSON document for a command line that cobra rejected.
func writeUsageJSON(w io.Writer, root *cobra.Command, args []string, err error) {
	doc := jsonDocument{
		ExitStatus: exitLocal,
		Error:      &failure{code: exitLocal, Title: "Invalid command line", Message: err.Error()},
	}
	if cmd, _, findErr := root.Find(args); findErr == nil && cmd != root {
		doc.Command = commandName(cmd)
	}
	_ = writeJSON(w, doc)
}

// toolVersion returns the version stamped into the binary. It returns "" when there is none.
func toolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	version, _ := buildVersion(info)
	return version
}

// handleError prints errors that a command has not already reported. fang capitalizes the first
// word of an error, which would turn a leading flag name such as --key-out into --Key-Out.
func handleError(w io.Writer, styles fang.Styles, err error) {
	if _, ok := errors.AsType[*exitError](err); ok {
		return
	}
	styles.ErrorText = styles.ErrorText.UnsetTransform()
	fang.DefaultErrorHandler(w, styles, err)
}

// newRootCommand returns the certrally command with its global flags.
func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   programName,
		Short: "Certificate enrollment client for CMP and EST",
		Long: "certrally is a certificate enrollment client for the Certificate Management Protocol (CMP) and " +
			"Enrollment over Secure Transport (EST).\n\n" +
			"It shows each exchange as a ladder diagram and explains failures. The CMP commands trust the CA " +
			"that answers their first request, unless --ca-cert names the CA to expect. The EST commands run " +
			"under certrally est.",
	}
	cmd.AddCommand(
		newEnrollCommand(),
		newRevokeCommand(),
		newCACertsCommand("cacerts"),
		newCMPCommand(),
		newESTCommand(),
		newPingCommand(),
		newInspectCommand(),
		newLintCommand(),
		newKeygenCommand(),
		newMockCommand(),
	)

	// Run applies the colour mode before parsing. The flag is still defined here so that help lists
	// it, an invalid value is rejected and shell completion offers the valid values.
	mode := colorFlag(termcolor.Auto)
	cmd.PersistentFlags().Var(&mode, "color", "when to colour output: auto, always or never")
	_ = cmd.RegisterFlagCompletionFunc("color", completeColorMode)

	// cobra defines --help and --version only after it has looked up the command to run. Until then
	// it assumes that an unknown flag takes a value, so "--help --color never" would make "never" an
	// unknown command. Only the root command rejects unknown commands, so only it needs the flags
	// early. cobra defines --version only for a command with a version, and fang replaces this
	// placeholder with the version of the build.
	cmd.Version = "unknown"
	cmd.InitDefaultHelpFlag()
	cmd.InitDefaultVersionFlag()
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

// colorModeFromArgs returns the --color value in args. It returns Auto when the flag is absent or invalid. An
// invalid value is reported later by cobra, with the rest of the command line.
func colorModeFromArgs(args []string) termcolor.Mode {
	fs := earlyFlagSet()
	mode := colorFlag(termcolor.Auto)
	fs.Var(&mode, "color", "")
	if err := fs.Parse(args); err != nil {
		return termcolor.Auto
	}
	return termcolor.Mode(mode)
}

// jsonFromArgs reports whether args ask for JSON output.
func jsonFromArgs(args []string) bool {
	fs := earlyFlagSet()
	asJSON := fs.Bool("json", false, "")
	return fs.Parse(args) == nil && *asJSON
}

// earlyFlagSet returns a flag set for reading single flags before cobra parses the command line.
// It ignores the flags it does not define.
func earlyFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet(programName, pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	// Without its own help flag, pflag stops at --help and ignores the flags that follow it.
	fs.BoolP("help", "h", false, "")
	return fs
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
// derived from the repository state into binaries built inside a Git checkout. That version is
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
