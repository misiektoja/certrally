package cli

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// TestShellQuote checks that the printed command survives a POSIX shell.
func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"device-42":        "device-42",
		"/tmp/ca.pem":      "/tmp/ca.pem",
		"my device":        "'my device'",
		"it's":             `'it'\''s'`,
		"$(touch x)":       "'$(touch x)'",
		"":                 "''",
		"C:\\certs\\a.pem": "'C:\\certs\\a.pem'",
	}
	for in, want := range tests {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCommandLine checks the order, quoting and value forms of a repeated command line.
func TestCommandLine(t *testing.T) {
	cmd := &cobra.Command{Use: "enroll"}
	(&cobra.Command{Use: "certrally"}).AddCommand(cmd)
	f := cmd.Flags()
	f.String("server", "", "")
	f.String("subject", "", "")
	f.String("unset", "", "")
	f.String("hidden", "", "")
	f.StringArray("san", nil, "")
	f.Bool("force", false, "")
	f.Bool("verify", true, "")
	f.Duration("timeout", time.Minute, "")
	for _, kv := range [][2]string{
		{"timeout", "30s"}, {"san", "a.example.com"}, {"san", "ip:192.0.2.7"}, {"force", "true"},
		{"verify", "false"}, {"subject", "CN=device 42"}, {"server", "http://ca.test/cmp"}, {"hidden", "x"},
	} {
		if err := f.Set(kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	got := commandLine(cmd, []string{"server", "subject", "san"}, "hidden")
	want := "certrally enroll --server http://ca.test/cmp --subject 'CN=device 42' --san a.example.com " +
		"--san ip:192.0.2.7 --force --timeout 30s --verify=false"
	if got != want {
		t.Errorf("commandLine =\n%s\nwant\n%s", got, want)
	}
}
