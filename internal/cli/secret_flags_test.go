package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretFlagCMP checks that mock, enroll and poll take the shared secret from --secret and that
// the flag cannot be combined with another source or with a signature.
func TestSecretFlagCMP(t *testing.T) {
	useSecret(t, "")
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--secret", testSecret,
		"--waiting", "1", "--check-after", "0s")
	if report := m.stdout.String(); !strings.Contains(report, "from --secret") || strings.Contains(report, testSecret) {
		t.Errorf("the startup report does not name --secret or shows the secret:\n%s", report)
	}
	dir := t.TempDir()
	t.Chdir(dir)

	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--secret", testSecret,
		"--subject", "CN=flag", "--cert-out", "cert.pem", "--key-out", "key.pem", "--poll-later", "--capture", "run.jsonl")
	if code != exitOK || !strings.Contains(out, "Request waiting for the CA") {
		t.Fatalf("enroll exited with %d:\n%s%s", code, out, errOut)
	}
	code, out, errOut = run(t, "poll", "--transaction-id", transactionIDIn(t, out), "--capture", "run.jsonl",
		"--secret", testSecret)
	if code != exitOK || !strings.Contains(out, "Certificate issued") {
		t.Fatalf("poll exited with %d:\n%s%s", code, out, errOut)
	}
	if got := readCert(t, "cert.pem").Subject.CommonName; got != "flag" {
		t.Errorf("issued CN=%s, want CN=flag", got)
	}

	outputs := func() []string {
		out := t.TempDir()
		return []string{"--cert-out", filepath.Join(out, "cert.pem"), "--key-out", filepath.Join(out, "key.pem")}
	}
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"wrong secret", []string{"--ref", testRef, "--secret", "wrong"}, exitRejected, ""},
		{"empty", []string{"--ref", testRef, "--secret="}, exitLocal, "must not be empty"},
		{"with --secret-file", []string{"--ref", testRef, "--secret", testSecret, "--secret-file", "secret.txt"}, exitLocal,
			"none of the others can be"},
		{"with --cert", []string{"--secret", testSecret, "--cert", "cert.pem", "--key", "key.pem"}, exitLocal,
			"choose one protection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(append([]string{"enroll", "--server", m.url, "--subject", "CN=x"}, outputs()...), tt.args...)
			code, _, errOut := run(t, args...)
			if code != tt.code || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.code, tt.want, errOut)
			}
		})
	}
}

// TestKeyPasswordFlag checks that --key-password decrypts an encrypted key and cannot be combined
// with --key-password-file.
func TestKeyPasswordFlag(t *testing.T) {
	useSecret(t, testSecret)
	useKeyPassword(t, "")
	ca := startCA(t, nil)
	keyFile, passwordFile := encryptedKeyFiles(t)
	certOut := filepath.Join(t.TempDir(), "cert.pem")
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--new-key", keyFile,
		"--key-password", encryptedKeyPassword, "--cert-out", certOut)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	checkEncryptedKeyCert(t, certOut)

	code, _, errOut = run(t, "enroll", "--server", ca.url, "--ref", testRef, "--new-key", keyFile,
		"--key-password", encryptedKeyPassword, "--key-password-file", passwordFile,
		"--cert-out", filepath.Join(t.TempDir(), "cert.pem"))
	if code != exitLocal || !errorContains(errOut, "none of the others can be") {
		t.Errorf("exited with %d, want 1 and a usage error in:\n%s", code, errOut)
	}
}

// TestESTSecretFlags checks --password and --token on est mock and est enroll. A bare --token keeps
// selecting the token sign-in, so a token on the client needs the = form.
func TestESTSecretFlags(t *testing.T) {
	usePassword(t, "")
	useToken(t, "")
	dir := t.TempDir()
	caOut, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token.txt")
	writeFile(t, tokenFile, []byte(estTestToken))
	m := startESTMock(t, "--listen", "127.0.0.1:0", "--user", estTestUser, "--password", estTestPassword,
		"--token", estTestToken, "--ca-out", caOut)
	report := m.stdout.String()
	for _, want := range []string{"from --password", "from --token"} {
		if !strings.Contains(report, want) {
			t.Errorf("startup report lacks %q:\n%s", want, report)
		}
	}
	for _, value := range []string{estTestPassword, estTestToken} {
		if strings.Contains(report, value) {
			t.Errorf("startup report shows %q:\n%s", value, report)
		}
	}

	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"password", []string{"--user", estTestUser, "--password", estTestPassword}, exitOK, ""},
		{"wrong password", []string{"--user", estTestUser, "--password", "wrong"}, exitRejected, ""},
		{"token", []string{"--token=" + estTestToken}, exitOK, ""},
		{"token after a space", []string{"--token", estTestToken}, exitLocal, "--token=TOKEN, with = instead of a space"},
		{"token with --token-file", []string{"--token=" + estTestToken, "--token-file", tokenFile}, exitLocal,
			"choose one source of the token"},
		{"password without user", []string{"--password", estTestPassword}, exitLocal, "--password needs --user"},
		{"password with --password-file", []string{"--user", estTestUser, "--password", estTestPassword,
			"--password-file", tokenFile}, exitLocal, "none of the others can be"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := "cert" + string(rune('a'+i))
			args := append([]string{"est", "enroll", "--server", m.url, "--tls-ca-cert", caOut, "--subject", "CN=" + name,
				"--cert-out", filepath.Join(dir, name+".pem"), "--key-out", filepath.Join(dir, name+".key")}, tt.args...)
			code, _, errOut := run(t, args...)
			if code != tt.code || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.code, tt.want, errOut)
			}
			if strings.Contains(errOut, estTestPassword) || strings.Contains(errOut, estTestToken) {
				t.Errorf("the error output shows the password or the token:\n%s", errOut)
			}
		})
	}
}

// TestEnrollWizardSecretFlags checks that the command the wizard prints leaves out the values of
// --secret and --key-password and says how that command gets them.
func TestEnrollWizardSecretFlags(t *testing.T) {
	useSecret(t, "")
	ca := startCA(t, nil)
	t.Chdir(t.TempDir())
	a := useWizard(t, map[string]string{
		"CA certificate":      "",
		"Request":             keep,
		"Subject":             keep,
		"Alternative names":   "",
		"Key type":            keep,
		"Save private key to": keep,
		"Send the request?":   "yes",
	})
	const keyPassword = "key-password-value"
	code, _, errOut := run(t, "enroll", "--interactive", "--server", ca.url, "--ref", testRef,
		"--secret", testSecret, "--key-password", keyPassword, "--cert-out", "device.pem")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if a.shown["Shared secret"] != "from --secret" {
		t.Errorf("shown shared secret = %q, want from --secret", a.shown["Shared secret"])
	}
	want := "certrally enroll --server " + ca.url + " --ref " + testRef + " --subject CN=" + testRef +
		" --cert-out device.pem --key-out device.key"
	if command := printedCommand(t, errOut); command != want {
		t.Errorf("printed command\n%s\nwant\n%s", command, want)
	}
	for _, value := range []string{testSecret, keyPassword} {
		if strings.Contains(errOut, value) {
			t.Errorf("the wizard printed %q:\n%s", value, errOut)
		}
	}
	for _, note := range []string{
		"That command asks for the shared secret unless CERTRALLY_SECRET, --secret or --secret-file provides it.",
		"That command asks for the key password unless CERTRALLY_KEY_PASSWORD, --key-password or " +
			"--key-password-file provides it.",
	} {
		if !errorContains(errOut, note) {
			t.Errorf("the wizard does not say %q:\n%s", note, errOut)
		}
	}
}
