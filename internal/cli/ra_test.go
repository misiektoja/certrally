package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// enrollRA enrolls a registration authority certificate with the cmcRA extended key usage from the
// CA at url and returns the certificate and key paths.
func enrollRA(t *testing.T, url, name string) (certOut, keyOut string) {
	t.Helper()
	return enrollIR(t, &testCA{url: url}, "--subject", "CN="+name, "--ext-key-usage", "cmcRA")
}

// TestEnrollRegistrationAuthority forwards MAC-protected and signed requests through a registration
// authority that certrally mock accepts. It checks the ladder, the report, the --json fields and the
// mock log. The strict profile turns any finding into a failure.
func TestEnrollRegistrationAuthority(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	raCert, raKey := enrollRA(t, m.url, "ra")
	deviceCert, deviceKey := enrollIR(t, &testCA{url: m.url}, "--subject", "CN=device")

	tests := []struct {
		name     string
		args     []string
		wantBody string
	}{
		{"MAC ir", []string{"--ref", testRef, "--subject", "CN=forwarded"}, "ir"},
		{"signed kur", []string{"--type", typeKUR, "--cert", deviceCert, "--key", deviceKey}, "kur"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"enroll", "--server", m.url, "--profile", "strict", "--ra-cert", raCert,
				"--ra-key", raKey, "--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem")},
				tt.args...)
			code, out, errOut := run(t, args...)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s%s", code, out, errOut)
			}
			for _, want := range []string{"nested(" + tt.wantBody + ")", "nested(certConf)"} {
				if !errorContains(errOut, want) {
					t.Errorf("ladder lacks %q:\n%s", want, errOut)
				}
			}
			if !strings.Contains(out, "Forwarded by  CN=ra") {
				t.Errorf("report lacks the RA:\n%s", out)
			}

			code, doc := runJSON(t, append(args, "--force")...)
			if code != exitOK || get(doc, "result.registrationAuthority") != "CN=ra" ||
				get(doc, "exchange.0.body") != "nested" || get(doc, "exchange.0.nested.0") != tt.wantBody ||
				get(doc, "exchange.1.nested") != nil || get(doc, "exchange.2.nested.0") != "certConf" {
				t.Errorf("exited with %d: %v", code, doc)
			}
		})
	}
	if !strings.Contains(m.stdout.String(), "forwarded by RA  CN=ra") {
		t.Errorf("the mock log does not note the RA:\n%s", m.stdout)
	}

	// A certificate without cmcRA does not make an RA.
	dir := t.TempDir()
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=x",
		"--ra-cert", deviceCert, "--ra-key", deviceKey,
		"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"))
	if code != exitRejected || !errorContains(errOut, "notAuthorized") || !errorContains(errOut, "lacks id-kp-cmcRA") {
		t.Errorf("exited with %d:\n%s%s", code, out, errOut)
	}

	code, _, errOut = run(t, "enroll", "--server", m.url, "--ref", testRef, "--ra-cert", raCert,
		"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"))
	if code != exitLocal || !errorContains(errOut, "ra-key") {
		t.Errorf("--ra-cert without --ra-key exited with %d:\n%s", code, errOut)
	}
}

// TestMockRequireRA checks that mock --require-ra refuses requests that no registration authority
// forwarded, except the one for an RA certificate.
func TestMockRequireRA(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--require-ra")
	if !strings.Contains(m.stdout.String(), "only requests a registration authority forwards") {
		t.Errorf("the startup report lacks --require-ra:\n%s", m.stdout)
	}
	raCert, raKey := enrollRA(t, m.url, "ra")
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")

	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=plain",
		"--cert-out", certOut, "--key-out", keyOut)
	if code != exitRejected || !errorContains(errOut, "accepts only requests that a registration authority forwards") {
		t.Errorf("a plain request exited with %d:\n%s%s", code, out, errOut)
	}
	code, out, errOut = run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=forwarded",
		"--ra-cert", raCert, "--ra-key", raKey, "--cert-out", certOut, "--key-out", keyOut)
	if code != exitOK {
		t.Fatalf("a forwarded request exited with %d:\n%s%s", code, out, errOut)
	}
	requireCertifiesKey(t, readCert(t, certOut), keyOut)
}

// TestPollRegistrationAuthority collects a waiting certificate through the registration authority
// that enroll used and through the one that poll --ra-cert names.
func TestPollRegistrationAuthority(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	raCert, raKey := enrollRA(t, m.url, "ra")
	otherCert, otherKey := enrollRA(t, m.url, "other-ra")
	t.Chdir(t.TempDir())
	later := func(name string) string {
		t.Helper()
		code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN="+name,
			"--ra-cert", raCert, "--ra-key", raKey, "--cert-out", name+".pem", "--key-out", name+".key",
			"--poll-later", "--capture", name+".jsonl")
		if code != exitOK || !strings.Contains(out, "Request waiting for the CA") {
			t.Fatalf("enroll exited with %d:\n%s%s", code, out, errOut)
		}
		return transactionIDIn(t, out)
	}

	id := later("recorded")
	code, out, errOut := run(t, "poll", "--transaction-id", id, "--capture", "recorded.jsonl")
	if code != exitOK || !strings.Contains(out, "Forwarded by    CN=ra") {
		t.Fatalf("poll exited with %d:\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"nested(pollReq)", "nested(certConf)"} {
		if !errorContains(errOut, want) {
			t.Errorf("ladder lacks %q:\n%s", want, errOut)
		}
	}
	requireCertifiesKey(t, readCert(t, "recorded.pem"), "recorded.key")

	id = later("moved")
	code, out, errOut = run(t, "poll", "--transaction-id", id, "--capture", "moved.jsonl",
		"--ra-cert", otherCert, "--ra-key", otherKey)
	if code != exitOK || !strings.Contains(out, "CN=other-ra") {
		t.Fatalf("poll --ra-cert exited with %d:\n%s%s", code, out, errOut)
	}
	if !strings.Contains(m.stdout.String(), "forwarded by RA  CN=other-ra") {
		t.Errorf("the mock log does not note the other RA:\n%s", m.stdout)
	}

	// The capture of a forwarded run breaks no rule.
	code, out, errOut = run(t, "lint", "recorded.jsonl")
	if code != exitOK || !strings.Contains(out, "No deviations") {
		t.Errorf("lint exited with %d:\n%s%s", code, out, errOut)
	}
}

// TestEnrollWizardRegistrationAuthority checks that the wizard keeps --ra-cert and --ra-key in the
// printed command.
func TestEnrollWizardRegistrationAuthority(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	raCert, raKey := enrollRA(t, m.url, "ra")
	t.Chdir(t.TempDir())
	useWizard(t, map[string]string{
		"CA certificate":      "",
		"Request":             keep,
		"Subject":             keep,
		"Alternative names":   "",
		"Key type":            keep,
		"Save certificate to": keep,
		"Save private key to": keep,
		"Send the request?":   "yes",
	})
	code, _, errOut := run(t, "enroll", "--interactive", "--server", m.url, "--ref", testRef,
		"--ra-cert", raCert, "--ra-key", raKey)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	want := "certrally enroll --server " + m.url + " --ref " + testRef + " --ra-cert " + raCert + " --ra-key " + raKey +
		" --subject CN=" + testRef + " --cert-out " + testRef + ".pem --key-out " + testRef + ".key"
	if command := printedCommand(t, errOut); command != want {
		t.Errorf("printed command\n%s\nwant\n%s", command, want)
	}
	if !errorContains(errOut, "nested(ir)") {
		t.Errorf("ladder lacks nested(ir):\n%s", errOut)
	}
}
