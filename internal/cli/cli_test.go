package cli

import (
	"bytes"
	"context"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

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
		if code != 1 || !strings.Contains(errOut, tt.want) {
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
		{"enroll"}, {"revoke"}, {"cacerts"}, {"ping"}, {"inspect"}, {"lint"}, {"keygen"}, {"mock"}, {"cmp"}, {"cmp", "genm"},
		{"cmp", "genm", "cacerts"}, {"cmp", "genm", "rootupdate"}, {"cmp", "genm", "template"},
		{"cmp", "genm", "crl"}, {"cmp", "genm", "crlupdate"}, {"cmp", "genm", "raw"},
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
