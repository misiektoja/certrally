// Package hack holds the tests of the maintenance scripts in this directory.
package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goPatchRun is one run of go-patch-version.sh against a release feed served from a file.
type goPatchRun struct {
	name string
	// feed is the JSON the script reads instead of go.dev.
	feed string
	// wantErr says whether the script must exit with a failure.
	wantErr bool
	// wantOutput must appear in the combined output.
	wantOutput string
	// wantGoMod is the go directive expected in go.mod after the run.
	wantGoMod string
}

// TestGoPatchVersionUpdate checks the update mode of go-patch-version.sh: it moves go.mod and the
// README to the newest stable patch of the series, leaves other series and prereleases alone and
// refuses a version from the feed that is not a plain dotted number, since the version is written
// into a sed expression.
func TestGoPatchVersionUpdate(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	script, err := filepath.Abs("go-patch-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	tests := []goPatchRun{
		{
			name:       "newer patch",
			feed:       `[{"version":"go1.28rc1","stable":false},{"version":"go1.27.9","stable":true},{"version":"go1.26.12","stable":true}]`,
			wantOutput: "updated",
			wantGoMod:  "go 1.27.9",
		},
		{
			name:       "up to date",
			feed:       `[{"version":"go1.27.3","stable":true}]`,
			wantOutput: "up to date",
			wantGoMod:  "go 1.27.3",
		},
		{
			name:       "sed delimiter in the version",
			feed:       `[{"version":"go1.27.9|w INJECTED","stable":true}]`,
			wantErr:    true,
			wantOutput: "not a plain dotted version",
			wantGoMod:  "go 1.27.3",
		},
		{
			name:       "newline in the version",
			feed:       `[{"version":"go1.27.9\nw INJECTED","stable":true}]`,
			wantErr:    true,
			wantOutput: "not a plain dotted version",
			wantGoMod:  "go 1.27.3",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			injected := filepath.Join(dir, "injected")
			goMod, readme, feed := filepath.Join(dir, "go.mod"), filepath.Join(dir, "README.md"), filepath.Join(dir, "releases.json")
			writeFile(t, goMod, "module example.com/m\n\ngo 1.27.3\n")
			writeFile(t, readme, "# m\n\nFrom source with Go 1.27.3 or newer:\n")
			writeFile(t, feed, strings.ReplaceAll(tc.feed, "INJECTED", injected))
			cmd := exec.Command("bash", script, "update")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GO_MOD="+goMod, "README="+readme, "RELEASES_URL=file://"+feed)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantErr {
				t.Errorf("exit error = %v, want failure %t:\n%s", err, tc.wantErr, out)
			}
			if !strings.Contains(string(out), tc.wantOutput) {
				t.Errorf("output lacks %q:\n%s", tc.wantOutput, out)
			}
			if got := goDirective(t, goMod); got != tc.wantGoMod {
				t.Errorf("go.mod declares %q, want %q", got, tc.wantGoMod)
			}
			// A sed w flag takes the rest of the expression as the file name.
			if written, _ := filepath.Glob(injected + "*"); len(written) > 0 {
				t.Errorf("the version from the feed reached sed and wrote %s", written)
			}
		})
	}
}

// writeFile writes a test fixture.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goDirective returns the go directive line of a go.mod file.
func goDirective(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "go ") {
			return line
		}
	}
	return ""
}
