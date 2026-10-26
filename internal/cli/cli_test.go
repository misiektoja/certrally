package cli

import (
	"bytes"
	"context"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/misiektoja/certrally/internal/termcolor"
)

// isolateColorEnv lets a test change the colour variables without leaking them to other tests.
func isolateColorEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

// run executes the command line and returns its exit status and output.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// errorContains reports whether the error output contains want when whitespace is ignored. When the
// writer is not a file, as in these tests, fang prints errors in a box that wraps at 120 columns, so
// a line break can fall anywhere in a message, even inside a long temporary path.
func errorContains(errOut, want string) bool {
	return strings.Contains(removeSpace(errOut), removeSpace(want))
}

// removeSpace returns s without any white space.
func removeSpace(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// TestRunHelp checks that help succeeds and lists the global flags.
func TestRunHelp(t *testing.T) {
	isolateColorEnv(t)
	for _, args := range [][]string{nil, {"--help"}, {"help"}} {
		code, out, _ := run(t, args...)
		if code != 0 {
			t.Errorf("%q exited with %d", args, code)
		}
		for _, want := range []string{"certrally", "--color", "--version"} {
			if !strings.Contains(out, want) {
				t.Errorf("%q output lacks %q:\n%s", args, want, out)
			}
		}
	}
}

// TestRunVersion checks that --version succeeds and names the program.
func TestRunVersion(t *testing.T) {
	isolateColorEnv(t)
	code, out, _ := run(t, "--version")
	if code != 0 || !strings.HasPrefix(out, "certrally version ") {
		t.Errorf("--version exited with %d and printed %q", code, out)
	}
}

// TestRunFlagAfterHelp checks that a flag with a separate value may follow --help, -h or --version.
func TestRunFlagAfterHelp(t *testing.T) {
	isolateColorEnv(t)
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--help", "--color", "never"}, "--version"},
		{[]string{"-h", "--color", "never"}, "--version"},
		{[]string{"--version", "--color", "never"}, "certrally version "},
		{[]string{"-v", "--color", "never"}, "certrally version "},
	}
	for _, tt := range tests {
		code, out, errOut := run(t, tt.args...)
		if code != 0 || !strings.Contains(out, tt.want) {
			t.Errorf("%q exited with %d:\n%s%s", tt.args, code, errOut, out)
		}
	}
}

// TestRunErrors checks that usage errors exit with status 1 and explain themselves on stderr.
func TestRunErrors(t *testing.T) {
	isolateColorEnv(t)
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--color", "purple"}, `invalid color mode "purple"`},
		{[]string{"no-such-command"}, "no-such-command"},
		{[]string{"--no-such-flag"}, "no-such-flag"},
	}
	for _, tt := range tests {
		code, _, errOut := run(t, tt.args...)
		if code != 1 || !errorContains(errOut, tt.want) {
			t.Errorf("%q exited with %d and wrote %q, want 1 and %q", tt.args, code, errOut, tt.want)
		}
	}
}

// TestRunAppliesColorMode checks that --color reaches the environment that colour detection reads.
func TestRunAppliesColorMode(t *testing.T) {
	isolateColorEnv(t)
	t.Setenv("FORCE_COLOR", "1")
	if code, _, _ := run(t, "--color", "never", "--help"); code != 0 {
		t.Fatalf("exited with %d", code)
	}
	if got := os.Getenv("NO_COLOR"); got != "1" {
		t.Errorf("NO_COLOR = %q after --color never", got)
	}
	if _, ok := os.LookupEnv("FORCE_COLOR"); ok {
		t.Error("FORCE_COLOR is still set after --color never")
	}
}

// TestColorCompletion checks that shell completion offers every --color value and no file names.
func TestColorCompletion(t *testing.T) {
	isolateColorEnv(t)
	code, out, _ := run(t, "__complete", "--color", "")
	if code != 0 {
		t.Fatalf("completion exited with %d", code)
	}
	got := strings.Fields(out)
	want := []string{"auto", "always", "never", ":4"}
	if !slices.Equal(got, want) {
		t.Errorf("completion printed %q, want %q", got, want)
	}
}

// TestColorModeFromArgs checks that the early parse finds --color wherever cobra would.
func TestColorModeFromArgs(t *testing.T) {
	tests := []struct {
		args []string
		want termcolor.Mode
	}{
		{nil, termcolor.Auto},
		{[]string{"--color", "never"}, termcolor.Never},
		{[]string{"--color=always"}, termcolor.Always},
		{[]string{"enroll", "--subject", "CN=x", "--color", "never"}, termcolor.Never},
		{[]string{"--color", "never", "--help"}, termcolor.Never},
		{[]string{"-h", "--color=always"}, termcolor.Always},
		{[]string{"-v", "--color", "never"}, termcolor.Never},
		{[]string{"--", "--color", "never"}, termcolor.Auto},
		{[]string{"--color", "purple"}, termcolor.Auto},
		{[]string{"--color"}, termcolor.Auto},
	}
	for _, tt := range tests {
		if got := colorModeFromArgs(tt.args); got != tt.want {
			t.Errorf("colorModeFromArgs(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

// TestBuildVersion checks which stamped versions are reported and when the revision is added.
func TestBuildVersion(t *testing.T) {
	const rev = "0123456789abcdef0123456789abcdef01234567"
	tests := []struct {
		name                    string
		version                 string
		wantVersion, wantCommit string
	}{
		{"no version", "", "", ""},
		{"development build", "(devel)", "", ""},
		{"release tag", "v0.1.0", "v0.1.0", rev},
		{"modified release tag", "v0.1.0+dirty", "v0.1.0+dirty", rev},
		{"pseudo-version", "v0.0.0-20261013010000-0123456789ab", "v0.0.0-20261013010000-0123456789ab", ""},
	}
	for _, tt := range tests {
		info := &debug.BuildInfo{
			Main:     debug.Module{Version: tt.version},
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: rev}},
		}
		version, commit := buildVersion(info)
		if version != tt.wantVersion || commit != tt.wantCommit {
			t.Errorf("%s: buildVersion = %q, %q, want %q, %q", tt.name, version, commit, tt.wantVersion, tt.wantCommit)
		}
	}
}

// TestCommandHelp checks that every command has help and that the root help lists the top-level ones.
func TestCommandHelp(t *testing.T) {
	isolateColorEnv(t)
	_, rootHelp, _ := run(t, "--help")
	commands := [][]string{
		{"enroll"}, {"poll"}, {"revoke"}, {"cacerts"}, {"ping"}, {"inspect"}, {"lint"}, {"keygen"}, {"mock"}, {"cmp"},
		{"cmp", "genm"},
		{"cmp", "genm", "cacerts"}, {"cmp", "genm", "rootupdate"}, {"cmp", "genm", "template"},
		{"cmp", "genm", "crl"}, {"cmp", "genm", "crlupdate"}, {"cmp", "genm", "raw"},
		{"cmp", "enroll"}, {"cmp", "poll"}, {"cmp", "revoke"}, {"cmp", "cacerts"}, {"cmp", "ping"}, {"cmp", "mock"},
		{"est"}, {"est", "cacerts"}, {"est", "csrattrs"}, {"est", "enroll"}, {"est", "reenroll"},
		{"est", "serverkeygen"}, {"est", "mock"},
	}
	for _, c := range commands {
		code, out, errOut := run(t, append(c, "--help")...)
		if code != 0 || !strings.Contains(out, "certrally "+strings.Join(c, " ")) {
			t.Errorf("%q --help exited with %d:\n%s%s", c, code, errOut, out)
		}
		if len(c) == 1 && !strings.Contains(rootHelp, c[0]) {
			t.Errorf("root help does not list %s", c[0])
		}
	}
}

// allCommands returns cmd and every command below it.
func allCommands(cmd *cobra.Command) []*cobra.Command {
	cmds := make([]*cobra.Command, 1, len(cmd.Commands())+1)
	cmds[0] = cmd
	for _, c := range cmd.Commands() {
		cmds = append(cmds, allCommands(c)...)
	}
	return cmds
}

// keepsCase reports whether s survives fang's styling of descriptions. fang title-cases their first
// word, which lowercases the rest of the word and capitalizes a letter after a hyphen, so that
// "CMP-specific" would read "Cmp-Specific".
func keepsCase(s string) bool {
	word, _, _ := strings.Cut(s, " ")
	for i, r := range word {
		if i > 0 && unicode.IsUpper(r) || r == '-' {
			return false
		}
	}
	return true
}

// TestHelpDescriptions checks that every command summary and flag description keeps its case in help.
func TestHelpDescriptions(t *testing.T) {
	for _, cmd := range allCommands(newRootCommand()) {
		if !keepsCase(cmd.Short) {
			t.Errorf("%s: summary %q changes case in help", cmd.CommandPath(), cmd.Short)
		}
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if !keepsCase(f.Usage) {
				t.Errorf("%s --%s: description %q changes case in help", cmd.CommandPath(), f.Name, f.Usage)
			}
		})
	}
}

// TestHelpWrapping checks that help does not break a line inside a flag name. fang may wrap at a
// hyphen. It wraps at 120 columns when standard output is not a terminal, as under go test ./...
func TestHelpWrapping(t *testing.T) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		t.Skip("fang wraps help to the width of the terminal")
	}
	isolateColorEnv(t)
	for _, cmd := range allCommands(newRootCommand()) {
		args := slices.Concat(strings.Fields(cmd.CommandPath())[1:], []string{"--help"})
		_, out, _ := run(t, args...)
		lines := strings.Split(out, "\n")
		for i := 0; i+1 < len(lines); i++ {
			line, next := strings.TrimRight(lines[i], " "), strings.TrimSpace(lines[i+1])
			// A lone -, as in "or - for standard input", may end a line.
			if !strings.HasSuffix(line, "-") || strings.HasSuffix(line, " -") && !strings.HasPrefix(next, "-") {
				continue
			}
			t.Errorf("%s --help breaks a word at a hyphen:\n%s\n%s", cmd.CommandPath(), line, next)
		}
	}
}

// TestExitStatusHelp checks that only enroll and poll, which confirm certificates, document exit status 5.
func TestExitStatusHelp(t *testing.T) {
	isolateColorEnv(t)
	commands := [][]string{
		{"enroll"}, {"poll"}, {"revoke"}, {"cacerts"}, {"cmp", "genm", "crl"}, {"cmp", "enroll"}, {"cmp", "poll"}, {"cmp", "revoke"},
	}
	for _, args := range commands {
		_, out, _ := run(t, append(args, "--help")...)
		name := args[len(args)-1]
		if got, want := strings.Contains(out, "5 issued"), name == "enroll" || name == "poll"; got != want {
			t.Errorf("%q --help mentions exit status 5: %v, want %v", args, got, want)
		}
	}
}
