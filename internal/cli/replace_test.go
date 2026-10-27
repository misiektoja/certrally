package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnrollReplacePrompt checks that enroll on a terminal asks before it replaces existing output
// files, sends nothing when the answer is no and does not ask with --force or --json.
func TestEnrollReplacePrompt(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "device.pem"), filepath.Join(dir, "device.key")
	old := []byte("old content\n")
	reset := func(t *testing.T) {
		t.Helper()
		writeFile(t, certOut, old)
		writeFile(t, keyOut, old)
	}
	enroll := func(t *testing.T, extra ...string) (int, string) {
		t.Helper()
		args := append([]string{"enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=device",
			"--cert-out", certOut, "--key-out", keyOut}, extra...)
		code, _, errOut := run(t, args...)
		return code, errOut
	}
	unchanged := func(t *testing.T) {
		t.Helper()
		for _, path := range []string{certOut, keyOut} {
			if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, old) {
				t.Errorf("%s was replaced: %v", path, err)
			}
		}
	}
	question := certOut + " and " + keyOut + " exist. Replace them?"

	t.Run("yes", func(t *testing.T) {
		reset(t)
		a := useWizard(t, map[string]string{question: "yes"})
		if code, errOut := enroll(t); code != exitOK {
			t.Fatalf("enroll exited with %d:\n%s", code, errOut)
		}
		if len(a.asked) != 1 {
			t.Errorf("asked %q, want one question", a.asked)
		}
		if readCert(t, certOut).Subject.CommonName != "device" {
			t.Error("the certificate was not replaced")
		}
	})
	for _, answer := range []string{"no", stop} {
		t.Run(answer, func(t *testing.T) {
			reset(t)
			useWizard(t, map[string]string{question: answer})
			requests := strings.Count(m.stdout.String(), "  ir  ")
			code, errOut := enroll(t)
			if code != exitLocal || !errorContains(errOut, "kept "+certOut+" and "+keyOut+". Choose other files or use --force") {
				t.Errorf("exited with %d, want 1 and the kept files in:\n%s", code, errOut)
			}
			unchanged(t)
			if strings.Count(m.stdout.String(), "  ir  ") != requests {
				t.Errorf("enroll sent a request after the answer %q:\n%s", answer, m.stdout)
			}
		})
	}
	t.Run("one file", func(t *testing.T) {
		reset(t)
		if err := os.Remove(keyOut); err != nil {
			t.Fatal(err)
		}
		a := useWizard(t, map[string]string{certOut + " exists. Replace it?": "no"})
		if code, _ := enroll(t); code != exitLocal || len(a.asked) != 1 {
			t.Errorf("exited with %d after %q, want 1 after one question", code, a.asked)
		}
	})
	t.Run("force", func(t *testing.T) {
		reset(t)
		useWizard(t, map[string]string{})
		if code, errOut := enroll(t, "--force"); code != exitOK {
			t.Errorf("enroll --force exited with %d:\n%s", code, errOut)
		}
	})
	t.Run("json", func(t *testing.T) {
		reset(t)
		useWizard(t, map[string]string{})
		code, doc := runJSON(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=device",
			"--cert-out", certOut, "--key-out", keyOut, "--json")
		if message, _ := get(doc, "error.message").(string); code != exitLocal || !strings.Contains(message, "already exists") {
			t.Errorf("exited with %d and error %v, want 1 and already exists", code, doc["error"])
		}
		unchanged(t)
	})
	t.Run("not a terminal", func(t *testing.T) {
		reset(t)
		code, errOut := enroll(t)
		if code != exitLocal || !errorContains(errOut, "already exists, use --force to replace it") {
			t.Errorf("exited with %d, want 1 and already exists in:\n%s", code, errOut)
		}
		unchanged(t)
	})
}

// TestKeygenReplacePrompt checks that keygen asks before it replaces an existing key file.
func TestKeygenReplacePrompt(t *testing.T) {
	isolateColorEnv(t)
	out := filepath.Join(t.TempDir(), "device.key")
	writeFile(t, out, []byte("old content\n"))
	useWizard(t, map[string]string{out + " exists. Replace it?": "yes"})
	if code, _, errOut := run(t, "keygen", "--out", out); code != exitOK {
		t.Fatalf("keygen exited with %d:\n%s", code, errOut)
	}
	if data, err := os.ReadFile(out); err != nil || !strings.Contains(string(data), "PRIVATE KEY") {
		t.Errorf("%s holds no new key: %v", out, err)
	}
}

// TestJoinList checks the lists that the replace question names.
func TestJoinList(t *testing.T) {
	tests := map[string][]string{
		"a":          {"a"},
		"a and b":    {"a", "b"},
		"a, b and c": {"a", "b", "c"},
	}
	for want, items := range tests {
		if got := joinList(items); got != want {
			t.Errorf("joinList(%q) = %q, want %q", items, got, want)
		}
	}
}
