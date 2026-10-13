package secret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// env returns a LookupEnv that knows only the given variables.
func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

// TestRead checks source precedence and line ending handling.
func TestRead(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte("from-file\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv := env(map[string]string{EnvVar: "from-env"})
	tests := []struct {
		name string
		src  Source
		want string
	}{
		{"file beats environment", Source{File: file, LookupEnv: withEnv}, "from-file"},
		{"environment", Source{LookupEnv: withEnv}, "from-env"},
		{"standard input", Source{File: "-", Stdin: strings.NewReader("piped\n\n")}, "piped\n"},
		{"inner spaces kept", Source{File: "-", Stdin: strings.NewReader(" a b ")}, " a b "},
	}
	for _, tt := range tests {
		got, err := tt.src.Read()
		if err != nil || string(got) != tt.want {
			t.Errorf("%s: %q, %v, want %q", tt.name, got, err, tt.want)
		}
	}
}

// TestReadErrors checks missing, empty and oversized secrets.
func TestReadErrors(t *testing.T) {
	if _, err := (Source{LookupEnv: env(nil), Stdin: strings.NewReader("")}).Read(); !errors.Is(err, ErrMissing) {
		t.Errorf("no source: %v", err)
	}
	if _, err := (Source{LookupEnv: env(map[string]string{EnvVar: ""})}).Read(); err == nil {
		t.Error("empty environment variable accepted")
	}
	if _, err := (Source{File: "-", Stdin: strings.NewReader("\n")}).Read(); err == nil {
		t.Error("empty line accepted")
	}
	big := strings.NewReader(strings.Repeat("x", maxSize+1))
	if _, err := (Source{File: "-", Stdin: big}).Read(); err == nil {
		t.Error("oversized secret accepted")
	}
	if _, err := (Source{File: filepath.Join(t.TempDir(), "missing")}).Read(); err == nil {
		t.Error("missing file accepted")
	}
}
