package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// TestRevoke checks a signed revocation, a second attempt and the CRL that lists the certificate.
func TestRevoke(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca, "--subject", "CN=device-42")
	cert := readCert(t, certFile)

	args := []string{"revoke", "--server", ca.url, "--cert", certFile, "--key", keyFile, "--reason", "keycompromise", "--yes"}
	code, out, errOut := run(t, args...)
	t.Log(errOut + out)
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	for _, want := range []string{"Certificate revoked", "CN=device-42", formatSerial(cert), "keyCompromise"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	for _, want := range []string{"rr", "rp  accepted"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("ladder lacks %q:\n%s", want, errOut)
		}
	}

	// The mock CA no longer accepts a signature from a revoked certificate.
	if code, _, errOut = run(t, args...); code != exitRejected {
		t.Errorf("second revocation exited with %d:\n%s", code, errOut)
	}

	crlFile := filepath.Join(t.TempDir(), "ca.crl")
	code, out, errOut = run(t, "cmp", "genm", "crl", "--server", ca.url, "--ref", testRef, "--out", crlFile)
	if code != exitOK || !strings.Contains(out, "Revoked      1") {
		t.Errorf("crl exited with %d:\n%s%s", code, errOut, out)
	}
}

// TestRevokeFailures checks rejected and invalid revocation requests.
func TestRevokeFailures(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca, "--subject", "CN=device-42")
	otherCA := startCA(t, nil)
	foreignFile, _ := enrollIR(t, otherCA)

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{"hold unsupported", []string{"--cert", certFile, "--key", keyFile, "--reason", "certificateHold"}, exitRejected, "does not accept this request"},
		{"other certificate", []string{"--cert", certFile, "--key", keyFile, "--revoke-cert", foreignFile}, exitRejected, "not authorized"},
		{"mac without target", []string{"--ref", testRef}, exitLocal, "--revoke-cert is required"},
		{"bad reason", []string{"--cert", certFile, "--key", keyFile, "--reason", "lost"}, exitLocal, "invalid --reason"},
		{"no protection", nil, exitLocal, "choose a protection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"revoke", "--server", ca.url, "--yes"}, tt.args...)
			code, _, errOut := run(t, args...)
			t.Log(errOut)
			if code != tt.wantCode || !strings.Contains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.wantCode, tt.want, errOut)
			}
		})
	}
}

// TestParseReason checks that every RFC 5280 reason name round-trips and that code 7 is refused.
func TestParseReason(t *testing.T) {
	for _, name := range reasonNames {
		r, err := parseReason(strings.ToUpper(name))
		if err != nil || r.String() != name {
			t.Errorf("parseReason(%q) = %v, %v", name, r, err)
		}
	}
	if len(reasonNames) != 10 {
		t.Errorf("%d reason names, want 10", len(reasonNames))
	}
	if _, err := parseReason("7"); err == nil {
		t.Error("parseReason accepted 7")
	}
	if r, _ := parseReason("removeFromCRL"); revokeTitle(r) != "Certificate released from hold" || revokeTitle(pkicmp.CRLReasonCertificateHold) != "Certificate placed on hold" {
		t.Error("hold titles")
	}
}

// TestConfirmWithoutTerminal checks that revocation does not wait for an answer when no one can give it.
func TestConfirmWithoutTerminal(t *testing.T) {
	var prompt strings.Builder
	ok, err := confirm(strings.NewReader("n\n"), &prompt, "Revoke?")
	if !ok || err != nil || prompt.Len() != 0 {
		t.Errorf("confirm = %v, %v, prompt %q", ok, err, prompt.String())
	}
}
