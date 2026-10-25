package cli

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// mockEnroll runs a MAC-protected enroll against m with the secret from the environment. It returns
// the exit status, the standard error and the capture file of the exchange.
func mockEnroll(t *testing.T, m *mockRun, extra ...string) (code int, errOut, capture string) {
	t.Helper()
	dir := t.TempDir()
	capture = filepath.Join(dir, "capture.jsonl")
	args := append([]string{"enroll", "--server", m.url, "--ref", testRef, "--capture", capture,
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem")}, extra...)
	code, _, errOut = run(t, args...)
	return code, errOut, capture
}

// reportHas checks that the startup report of m shows a field.
func reportHas(t *testing.T, m *mockRun, want string) {
	t.Helper()
	if !strings.Contains(m.stdout.String(), want) {
		t.Errorf("startup report lacks %q:\n%s", want, m.stdout)
	}
}

// TestMockWaiting checks that --waiting delays certificate and revocation requests until the polls.
func TestMockWaiting(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "2", "--check-after", "0s")
	reportHas(t, m, "decides on poll 2, checkAfter 0s")
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, _, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if n := strings.Count(m.stdout.String(), "pollReq"); n != 2 {
		t.Errorf("the mock answered %d polls, want 2:\n%s", n, m.stdout)
	}
	code, _, errOut = run(t, "revoke", "--server", m.url, "--cert", certOut, "--key", keyOut, "--yes")
	if code != exitOK {
		t.Fatalf("revoke exited with %d:\n%s", code, errOut)
	}
	if n := strings.Count(m.stdout.String(), "pollReq"); n != 4 {
		t.Errorf("the mock answered %d polls, want 4:\n%s", n, m.stdout)
	}
}

// TestMockReject checks that --reject refuses every request with the given failInfo and text, at
// once or after the polls of --waiting.
func TestMockReject(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--reject", "badCertTemplate:subject not allowed")
	reportHas(t, m, "badCertTemplate:subject not allowed")
	code, errOut, _ := mockEnroll(t, m)
	if code != exitRejected || !errorContains(errOut, "badCertTemplate") || !errorContains(errOut, "subject not allowed") {
		t.Errorf("enroll exited with %d, want %d with the rejection:\n%s", code, exitRejected, errOut)
	}

	delayed := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--reject", "badRequest", "--waiting", "1", "--check-after", "0s")
	code, errOut, _ = mockEnroll(t, delayed)
	if code != exitRejected || !errorContains(errOut, "badRequest") {
		t.Errorf("enroll exited with %d, want %d with badRequest:\n%s", code, exitRejected, errOut)
	}
	if n := strings.Count(delayed.stdout.String(), "pollReq"); n != 1 {
		t.Errorf("the mock answered %d polls before the rejection, want 1:\n%s", n, delayed.stdout)
	}
}

// TestMockImplicitConfirm checks that --grant-implicit-confirm grants implicitConfirm to a request
// that asks for it, which certrally does through --general-info, and not to one that does not.
func TestMockImplicitConfirm(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--grant-implicit-confirm")
	reportHas(t, m, "implicitConfirm granted")
	implicitConfirm := pkicmp.ImplicitConfirmInfoValue().InfoType
	granted := func(capture string) bool {
		t.Helper()
		ip, err := pkicmp.ParsePKIMessage(readCapture(t, capture)[1].DER)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(ip.Header.GeneralInfo, func(item pkicmp.InfoTypeAndValue) bool { return item.InfoType.Equal(implicitConfirm) })
	}

	// certrally does not yet skip the certConf when the CA grants implicit confirmation, so the
	// exchange ends with the CA refusing a certConf for a closed transaction. Only the grant matters here.
	_, _, capture := mockEnroll(t, m, "--general-info", implicitConfirm.String()+":hex:0500")
	if !granted(capture) {
		t.Error("the ip does not grant implicitConfirm to a request that asks for it")
	}

	code, errOut, capture := mockEnroll(t, m)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if granted(capture) {
		t.Error("the ip grants implicitConfirm to a request that did not ask for it")
	}
}

// TestMockStrict checks that --strict still accepts the conforming requests certrally sends.
func TestMockStrict(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--strict")
	reportHas(t, m, "strict")
	if code, errOut, _ := mockEnroll(t, m); code != exitOK {
		t.Errorf("enroll exited with %d:\n%s", code, errOut)
	}
}

// TestMockMACIterations checks that --mac-iterations bounds the count a request may use and that
// --iterations sends a count outside the client defaults.
func TestMockMACIterations(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--mac-iterations", "20000-600000")
	reportHas(t, m, "20000-600000")
	if code, errOut, _ := mockEnroll(t, m); code != exitRejected {
		t.Errorf("enroll with the default count exited with %d, want %d:\n%s", code, exitRejected, errOut)
	}
	if code, errOut, _ := mockEnroll(t, m, "--iterations", "600000"); code != exitOK {
		t.Errorf("enroll with 600000 iterations exited with %d:\n%s", code, errOut)
	}
}

// TestMockAcceptSHA1 checks that SHA-1 signatures are refused unless --accept sha1 is given.
func TestMockAcceptSHA1(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	code, errOut, _ := mockEnroll(t, m, "--mac", "pbm", "--hash", "sha1")
	if code != exitRejected || !errorContains(errOut, "badAlg") {
		t.Errorf("enroll with SHA-1 exited with %d, want %d with badAlg:\n%s", code, exitRejected, errOut)
	}

	lenient := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--accept", "sha1")
	reportHas(t, lenient, "Accepting")
	reportHas(t, lenient, "sha1")
	if code, errOut, _ := mockEnroll(t, lenient, "--mac", "pbm", "--hash", "sha1"); code != exitOK {
		t.Errorf("enroll with SHA-1 exited with %d:\n%s", code, errOut)
	}
}

// TestMockConfirmWait checks that --confirm-wait sets the confirmWaitTime of the response.
func TestMockConfirmWait(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--confirm-wait", "1h")
	reportHas(t, m, "1h0m0s")
	before := time.Now()
	code, errOut, capture := mockEnroll(t, m)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	ip, err := pkicmp.ParsePKIMessage(readCapture(t, capture)[1].DER)
	if err != nil {
		t.Fatal(err)
	}
	var deadline time.Time
	for _, item := range ip.Header.GeneralInfo {
		if d, err := pkicmp.ParseConfirmWaitTime(item); err == nil {
			deadline = d
		}
	}
	if deadline.Before(before.Add(55*time.Minute)) || deadline.After(before.Add(65*time.Minute)) {
		t.Errorf("confirmWaitTime = %v, want about an hour after %v", deadline, before)
	}
}

// TestMockMACRevocation checks that a MAC-protected revocation needs --accept mac-revocation.
func TestMockMACRevocation(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, _, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	code, _, errOut = run(t, "revoke", "--server", m.url, "--ref", testRef, "--revoke-cert", certOut, "--yes")
	if code != exitRejected || !errorContains(errOut, "wrongIntegrity") {
		t.Errorf("revoke exited with %d, want %d with wrongIntegrity:\n%s", code, exitRejected, errOut)
	}

	lenient := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--accept", "mac-revocation")
	code, _, errOut = run(t, "enroll", "--server", lenient.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut, "--force")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	code, _, errOut = run(t, "revoke", "--server", lenient.url, "--ref", testRef, "--revoke-cert", certOut, "--yes")
	if code != exitOK {
		t.Errorf("revoke exited with %d:\n%s", code, errOut)
	}
}

// TestMockFaultErrors checks that the mock CA refuses bad fault flags before it listens.
func TestMockFaultErrors(t *testing.T) {
	useSecret(t, testSecret)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"negative waiting", []string{"--waiting", "-1"}, "--waiting must not be negative"},
		{"negative check-after", []string{"--check-after", "-1s"}, "--check-after must not be negative"},
		{"zero confirm-wait", []string{"--confirm-wait", "0s"}, "--confirm-wait must be positive"},
		{"unknown failInfo", []string{"--reject", "badLuck"}, "invalid --reject"},
		{"iteration range", []string{"--mac-iterations", "100"}, "invalid --mac-iterations"},
		{"reversed iteration range", []string{"--mac-iterations", "100-10"}, "invalid --mac-iterations"},
		{"zero iteration minimum", []string{"--mac-iterations", "0-10"}, "invalid --mac-iterations"},
		{"unknown accept", []string{"--accept", "everything"}, "invalid --accept"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, append([]string{"mock", "--listen", "127.0.0.1:0"}, tt.args...)...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d with %q:\n%s", code, exitLocal, tt.want, errOut)
			}
		})
	}
}
