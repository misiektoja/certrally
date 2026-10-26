package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/misiektoja/certrally/internal/secret"
)

// estTestToken is the bearer token the tests sign in with.
const estTestToken = "tok-4f2a9c"

// useToken makes the bearer token available through the environment, or removes it when empty.
func useToken(t *testing.T, value string) {
	t.Helper()
	t.Setenv(secret.TokenEnvVar, value)
	if value == "" {
		if err := os.Unsetenv(secret.TokenEnvVar); err != nil {
			t.Fatal(err)
		}
	}
}

// TestESTToken checks that --token-file and --token sign in with a bearer token against est mock
// --token-file, that a wrong token is refused with a hint and that the startup report shows the
// token.
func TestESTToken(t *testing.T) {
	usePassword(t, "")
	useToken(t, "")
	dir := t.TempDir()
	passwordFile, tokenFile, caOut := filepath.Join(dir, "password.txt"), filepath.Join(dir, "token.txt"), filepath.Join(dir, "ca.pem")
	writeFile(t, passwordFile, []byte(estTestPassword))
	writeFile(t, tokenFile, []byte(estTestToken+"\n"))
	m := startESTMock(t, "--listen", "127.0.0.1:0", "--user", estTestUser, "--password-file", passwordFile,
		"--token-file", tokenFile, "--ca-out", caOut)
	report := m.stdout.String()
	for _, want := range []string{"Token", "from " + tokenFile, "--token-file " + tokenFile + " --subject"} {
		if !strings.Contains(report, want) {
			t.Errorf("startup report lacks %q:\n%s", want, report)
		}
	}
	enroll := func(t *testing.T, name string, extra ...string) (int, map[string]any) {
		t.Helper()
		args := append([]string{"est", "enroll", "--server", m.url, "--tls-ca-cert", caOut}, extra...)
		return runJSON(t, append(args, "--subject", "CN="+name,
			"--cert-out", filepath.Join(dir, name+".pem"), "--key-out", filepath.Join(dir, name+".key"))...)
	}

	t.Run("token file", func(t *testing.T) {
		code, doc := enroll(t, "file", "--token-file", tokenFile)
		if code != exitOK {
			t.Fatalf("exit %d, error %v", code, doc["error"])
		}
		if readCert(t, filepath.Join(dir, "file.pem")).Subject.CommonName != "file" {
			t.Error("the certificate has another subject")
		}
	})
	t.Run("reenroll without key", func(t *testing.T) {
		code, doc := runJSON(t, "est", "reenroll", "--server", m.url, "--tls-ca-cert", caOut, "--token-file", tokenFile,
			"--cert", filepath.Join(dir, "file.pem"), "--cert-out", filepath.Join(dir, "renewed.pem"),
			"--key-out", filepath.Join(dir, "renewed.key"))
		if code != exitOK || estRequestOperations(doc) != "simplereenroll" {
			t.Errorf("exit %d, requests %q, error %v", code, estRequestOperations(doc), doc["error"])
		}
	})
	t.Run("environment", func(t *testing.T) {
		useToken(t, estTestToken)
		if code, doc := enroll(t, "env", "--token"); code != exitOK {
			t.Errorf("enroll: exit %d, error %v", code, doc["error"])
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		useToken(t, "wrong")
		code, doc := enroll(t, "wrong", "--token")
		if code != exitRejected || get(doc, "error.httpStatus") != float64(http.StatusUnauthorized) ||
			get(doc, "error.hint") != "Check the token." {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})
	t.Run("password", func(t *testing.T) {
		if code, doc := enroll(t, "password", "--user", estTestUser, "--password-file", passwordFile); code != exitOK {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})
	t.Run("no credentials", func(t *testing.T) {
		code, doc := enroll(t, "none")
		if code != exitRejected || get(doc, "error.hint") != "Sign in with --user and a password, with --token, or with --cert and --key." {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})

	if code := m.stop(t); code != exitOK {
		t.Errorf("est mock exited with %d:\n%s", code, m.stderr)
	}
	if output := m.stdout.String(); !strings.Contains(output, "POST  simpleenroll  CN=file  ->  HTTP 200  certs-only") {
		t.Errorf("log lacks the token enroll:\n%s", output)
	}
}

// TestESTMockTokenEnv checks that est mock takes the token from the environment without
// --token-file and prints an enroll command with --token.
func TestESTMockTokenEnv(t *testing.T) {
	usePassword(t, estTestPassword)
	useToken(t, estTestToken)
	m := startESTMock(t, "--listen", "127.0.0.1:0", "--user", estTestUser)
	report := m.stdout.String()
	for _, want := range []string{"from " + secret.TokenEnvVar, "--tls-ca-cert ca.pem --token --subject"} {
		if !strings.Contains(report, want) {
			t.Errorf("startup report lacks %q:\n%s", want, report)
		}
	}
	dir := t.TempDir()
	code, doc := runJSON(t, "est", "enroll", "--server", m.url, "--insecure", "--token", "--subject", "CN=env",
		"--cert-out", filepath.Join(dir, "env.pem"), "--key-out", filepath.Join(dir, "env.key"))
	if code != exitOK {
		t.Errorf("exit %d, error %v", code, doc["error"])
	}
}

// TestESTMockNoToken checks that est mock without a token refuses a bearer token and says so in
// the startup report.
func TestESTMockNoToken(t *testing.T) {
	usePassword(t, estTestPassword)
	useToken(t, "")
	m := startESTMock(t, "--listen", "127.0.0.1:0", "--user", estTestUser)
	if report := m.stdout.String(); !regexp.MustCompile(`Token\s+none`).MatchString(report) || strings.Contains(report, "--token") {
		t.Errorf("startup report should say there is no token:\n%s", report)
	}
	useToken(t, estTestToken)
	dir := t.TempDir()
	code, doc := runJSON(t, "est", "enroll", "--server", m.url, "--insecure", "--token", "--subject", "CN=none",
		"--cert-out", filepath.Join(dir, "none.pem"), "--key-out", filepath.Join(dir, "none.key"))
	if code != exitRejected || get(doc, "error.hint") != "Check the token." {
		t.Errorf("exit %d, error %v", code, doc["error"])
	}
}
