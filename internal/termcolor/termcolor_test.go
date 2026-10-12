package termcolor

import (
	"bytes"
	"os"
	"slices"
	"testing"

	"github.com/charmbracelet/colorprofile"
)

// TestParseMode checks that only the documented modes are accepted.
func TestParseMode(t *testing.T) {
	for _, m := range Modes {
		got, err := ParseMode(string(m))
		if err != nil || got != m {
			t.Errorf("ParseMode(%q) = %q, %v", m, got, err)
		}
	}
	for _, s := range []string{"", "AUTO", "yes", "true", "none"} {
		if _, err := ParseMode(s); err == nil {
			t.Errorf("ParseMode(%q) accepted an invalid mode", s)
		}
	}
}

// TestEnvironDetection checks the profile colorprofile detects from the rewritten environment.
// TTY_FORCE stands in for a terminal, which colorprofile cannot see behind a buffer.
func TestEnvironDetection(t *testing.T) {
	const term = "TERM=xterm-256color"
	const tty = "TTY_FORCE=1"
	tests := []struct {
		name  string
		mode  Mode
		env   []string
		color bool
	}{
		{"auto on a terminal", Auto, []string{term, tty}, true},
		{"auto on a pipe", Auto, []string{term}, false},
		{"auto with a dumb terminal", Auto, []string{"TERM=dumb", tty}, false},
		{"NO_COLOR=1 on a terminal", Auto, []string{term, tty, "NO_COLOR=1"}, false},
		{"NO_COLOR with a non-boolean value", Auto, []string{term, tty, "NO_COLOR=yes"}, false},
		{"empty NO_COLOR is ignored", Auto, []string{term, tty, "NO_COLOR="}, true},
		{"FORCE_COLOR on a pipe", Auto, []string{term, "FORCE_COLOR=1"}, true},
		{"FORCE_COLOR level on a pipe", Auto, []string{term, "FORCE_COLOR=3"}, true},
		{"FORCE_COLOR=0 does not force", Auto, []string{term, "FORCE_COLOR=0"}, false},
		{"FORCE_COLOR=false does not force", Auto, []string{term, "FORCE_COLOR=false"}, false},
		{"CLICOLOR_FORCE on a pipe", Auto, []string{term, "CLICOLOR_FORCE=1"}, true},
		{"NO_COLOR beats CLICOLOR_FORCE on a pipe", Auto, []string{term, "CLICOLOR_FORCE=1", "NO_COLOR=1"}, false},
		{"NO_COLOR beats FORCE_COLOR on a pipe", Auto, []string{term, "FORCE_COLOR=1", "NO_COLOR=yes"}, false},
		{"always on a pipe", Always, []string{term}, true},
		{"always without TERM", Always, nil, true},
		{"always beats NO_COLOR", Always, []string{term, tty, "NO_COLOR=1"}, true},
		{"never on a terminal", Never, []string{term, tty}, false},
		{"never beats FORCE_COLOR", Never, []string{term, "FORCE_COLOR=1"}, false},
		{"never beats CLICOLOR_FORCE", Never, []string{term, "CLICOLOR_FORCE=1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := colorprofile.Detect(&bytes.Buffer{}, Environ(tt.mode, tt.env))
			if got := p >= colorprofile.ANSI; got != tt.color {
				t.Errorf("detected profile %v, want color=%v", p, tt.color)
			}
		})
	}
}

// TestEnvironKeepsOtherVariables checks that only the colour variables are rewritten.
func TestEnvironKeepsOtherVariables(t *testing.T) {
	env := []string{"HOME=/home/u", "TERM=xterm", "FORCE_COLOR=2", "NO_COLOR=", "PATH=/bin"}
	got := Environ(Auto, env)
	want := []string{"HOME=/home/u", "TERM=xterm", "FORCE_COLOR=2", "PATH=/bin", "CLICOLOR_FORCE=1"}
	if !slices.Equal(got, want) {
		t.Errorf("Environ = %q, want %q", got, want)
	}
	if env[3] != "NO_COLOR=" {
		t.Errorf("Environ modified its input: %q", env)
	}

	got = Environ(Never, env)
	want = []string{"HOME=/home/u", "TERM=xterm", "PATH=/bin", "NO_COLOR=1"}
	if !slices.Equal(got, want) {
		t.Errorf("Environ(Never) = %q, want %q", got, want)
	}
}

// TestApply checks that the process environment follows the mode.
func TestApply(t *testing.T) {
	t.Setenv("NO_COLOR", "yes")
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "1")

	if err := Apply(Never); err != nil {
		t.Fatal(err)
	}
	assertEnv(t, "NO_COLOR", "1", true)
	assertEnv(t, "FORCE_COLOR", "", false)
	assertEnv(t, "CLICOLOR_FORCE", "", false)

	if err := Apply(Always); err != nil {
		t.Fatal(err)
	}
	assertEnv(t, "NO_COLOR", "", false)
	assertEnv(t, "CLICOLOR_FORCE", "1", true)
}

// assertEnv fails the test unless the process environment holds key with value, or lacks key.
func assertEnv(t *testing.T, key, value string, present bool) {
	t.Helper()
	got, ok := os.LookupEnv(key)
	if ok != present || got != value {
		t.Errorf("%s = %q (set %v), want %q (set %v)", key, got, ok, value, present)
	}
}
