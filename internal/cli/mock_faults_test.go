package cli

import (
	"encoding/json"
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
// that asks for it with --implicit-confirm, which then ends without certConf, and not to one that
// does not ask. Without the fault flag the request is confirmed as usual.
func TestMockImplicitConfirm(t *testing.T) {
	useSecret(t, testSecret)
	implicitConfirm := pkicmp.ImplicitConfirmInfoValue().InfoType
	hasImplicitConfirm := func(h pkicmp.PKIHeader) bool {
		return slices.ContainsFunc(h.GeneralInfo, func(item pkicmp.InfoTypeAndValue) bool { return item.InfoType.Equal(implicitConfirm) })
	}
	// exchange returns the number of messages in a capture and whether the request asked for
	// implicit confirmation and the response granted it.
	exchange := func(capture string) (n int, requested, granted bool) {
		t.Helper()
		msgs := readCapture(t, capture)
		ir, err := pkicmp.ParsePKIMessage(msgs[0].DER)
		if err != nil {
			t.Fatal(err)
		}
		ip, err := pkicmp.ParsePKIMessage(msgs[1].DER)
		if err != nil {
			t.Fatal(err)
		}
		return len(msgs), hasImplicitConfirm(ir.Header), hasImplicitConfirm(ip.Header)
	}

	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--grant-implicit-confirm")
	reportHas(t, m, "implicitConfirm granted")
	code, errOut, capture := mockEnroll(t, m, "--implicit-confirm")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if n, requested, granted := exchange(capture); n != 2 || !requested || !granted {
		t.Errorf("the exchange has %d messages, requested %v, granted %v, want 2 with the request and the grant", n, requested, granted)
	}

	code, errOut, capture = mockEnroll(t, m)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if n, requested, granted := exchange(capture); n != 4 || requested || granted {
		t.Errorf("the exchange has %d messages, requested %v, granted %v, want 4 without a request or a grant", n, requested, granted)
	}

	plain := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	code, errOut, capture = mockEnroll(t, plain, "--implicit-confirm")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if n, requested, granted := exchange(capture); n != 4 || !requested || granted {
		t.Errorf("the exchange has %d messages, requested %v, granted %v, want 4 with the request and no grant", n, requested, granted)
	}
}

// TestEnrollImplicitConfirmResult checks that the result says how the certificate was confirmed.
func TestEnrollImplicitConfirmResult(t *testing.T) {
	useSecret(t, testSecret)
	granting := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--grant-implicit-confirm")
	plain := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	tests := []struct {
		name     string
		m        *mockRun
		args     []string
		implicit bool
		field    string
	}{
		{"granted", granting, []string{"--implicit-confirm"}, true, "implicit, no certConf sent"},
		{"not granted", plain, []string{"--implicit-confirm"}, false, "did not grant implicit confirmation"},
		{"not asked", plain, nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"enroll", "--server", tt.m.url, "--ref", testRef,
				"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem")}, tt.args...)
			code, out, errOut := run(t, args...)
			if code != exitOK {
				t.Fatalf("enroll exited with %d:\n%s", code, errOut)
			}
			if got := strings.Contains(out, fieldConfirmation); got != (tt.field != "") || (tt.field != "" && !strings.Contains(out, tt.field)) {
				t.Errorf("the report shows the confirmation as %q, want %q:\n%s", fieldConfirmation, tt.field, out)
			}

			code, out, errOut = run(t, append(args, "--json", "--force")...)
			if code != exitOK {
				t.Fatalf("enroll --json exited with %d:\n%s", code, errOut)
			}
			var doc struct {
				Result struct {
					Confirmed       bool `json:"confirmed"`
					ImplicitConfirm bool `json:"implicitConfirm"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("standard output is not JSON: %v\n%s", err, out)
			}
			if !doc.Result.Confirmed || doc.Result.ImplicitConfirm != tt.implicit {
				t.Errorf("confirmed = %v, implicitConfirm = %v, want true and %v", doc.Result.Confirmed, doc.Result.ImplicitConfirm, tt.implicit)
			}
		})
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
	if !strings.Contains(lenient.stdout.String(), "revoked  serial "+formatSerial(readCert(t, certOut))+"  unspecified") {
		t.Errorf("mock log lacks the revocation:\n%s", lenient.stdout)
	}

	// An authority that has only the serial number names the certificate with --serial and --issuer.
	code, _, errOut = run(t, "enroll", "--server", lenient.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut, "--force")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	cert := readCert(t, certOut)
	code, _, errOut = run(t, "revoke", "--server", lenient.url, "--ref", testRef, "--serial", formatSerial(cert),
		"--issuer", "CN=Test CA", "--reason", "keyCompromise", "--invalidity-date", "2026-10-01", "--yes")
	if code != exitOK {
		t.Errorf("revoke by serial exited with %d:\n%s", code, errOut)
	}
	want := "revoked  serial " + formatSerial(cert) + "  keyCompromise  invalidity date 2026-10-01T00:00:00Z"
	if !strings.Contains(lenient.stdout.String(), want) {
		t.Errorf("mock log lacks %q:\n%s", want, lenient.stdout)
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
