package cli

import (
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/dn"
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
		if !errorContains(errOut, want) {
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

// TestRevokeBySerial checks a revocation that names the certificate by issuer and serial number
// and gives an invalidity date, signed with that certificate.
func TestRevokeBySerial(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca, "--subject", "CN=device-42")
	cert := readCert(t, certFile)
	issuer := dn.Format(cert.RawIssuer)

	code, out, errOut := run(t, "revoke", "--server", ca.url, "--cert", certFile, "--key", keyFile,
		"--serial", formatSerial(cert), "--issuer", issuer, "--reason", "keyCompromise",
		"--invalidity-date", "2026-10-01", "--yes")
	t.Log(errOut + out)
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	for _, want := range []string{"Certificate revoked", issuer, formatSerial(cert), "keyCompromise", "Invalidity date", "2026-10-01 00:00 UTC"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Subject") {
		t.Errorf("report names a subject the request did not carry:\n%s", out)
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
	issuer := dn.Format(readCert(t, certFile).RawIssuer)

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{"hold unsupported", []string{"--cert", certFile, "--key", keyFile, "--reason", "certificateHold"}, exitRejected, "does not accept this request"},
		{"other certificate", []string{"--cert", certFile, "--key", keyFile, "--revoke-cert", foreignFile}, exitRejected, "not authorized"},
		{"other serial", []string{"--cert", certFile, "--key", keyFile, "--serial", "0x1A", "--issuer", issuer}, exitRejected, "not authorized"},
		{"mac without target", []string{"--ref", testRef}, exitLocal, "--revoke-cert, or --serial with --issuer, is required"},
		{"serial without issuer", []string{"--ref", testRef, "--serial", "0x1A"}, exitLocal, "--serial and --issuer are given together"},
		{"issuer without serial", []string{"--ref", testRef, "--issuer", issuer}, exitLocal, "--serial and --issuer are given together"},
		{"serial and file", []string{"--ref", testRef, "--serial", "0x1A", "--issuer", issuer, "--revoke-cert", certFile}, exitLocal, "name the certificate twice"},
		{"bad serial", []string{"--ref", testRef, "--serial", "1A", "--issuer", issuer}, exitLocal, "invalid --serial"},
		{"bad issuer", []string{"--ref", testRef, "--serial", "0x1A", "--issuer", "XX=1"}, exitLocal, "--issuer: unknown attribute type"},
		{"bad invalidity date", []string{"--cert", certFile, "--key", keyFile, "--invalidity-date", "yesterday"}, exitLocal, "invalid --invalidity-date"},
		{"bad reason", []string{"--cert", certFile, "--key", keyFile, "--reason", "lost"}, exitLocal, "invalid --reason"},
		{"no protection", nil, exitLocal, "choose a protection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"revoke", "--server", ca.url, "--yes"}, tt.args...)
			code, _, errOut := run(t, args...)
			t.Log(errOut)
			if code != tt.wantCode || !errorContains(errOut, tt.want) {
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

// TestParseSerial checks the decimal, 0x hex and colon-separated hex forms of --serial.
func TestParseSerial(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"4242", 4242},
		{"0", 0},
		{"0x1A", 0x1a},
		{"0X1a", 0x1a},
		{"1A:2B", 0x1a2b},
		{"1a:2b:3c", 0x1a2b3c},
		{"0:FF", 0xff},
	}
	for _, tt := range tests {
		got, err := parseSerial(tt.in)
		if err != nil || got.Cmp(big.NewInt(tt.want)) != 0 {
			t.Errorf("parseSerial(%q) = %v, %v, want %d", tt.in, got, err, tt.want)
		}
	}
	printed := "C3:9F:8E:A1:02:7B:11:5C:44:D0:9E:71:33:0A:F5"
	if long, err := parseSerial(printed); err != nil || long.BitLen() != 120 || hexBytes(long.Bytes()) != printed {
		t.Errorf("parseSerial(%q) = %v, %v", printed, long, err)
	}
	for _, in := range []string{"", "1A", "-5", "+5", "0x", "0x-1", "0xZZ", "1A::2B", ":1A", "1A:", "1A:2G", "1_000"} {
		if got, err := parseSerial(in); err == nil {
			t.Errorf("parseSerial(%q) = %v, want an error", in, got)
		}
	}
}

// TestParseInvalidityDate checks the RFC 3339 and date forms of --invalidity-date.
func TestParseInvalidityDate(t *testing.T) {
	tests := []struct {
		in   string
		want time.Time
	}{
		{"2026-10-01", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		{"2026-10-01T12:00:00Z", time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		{"2026-10-01T12:00:00+02:00", time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)},
		{"2026-10-01T12:00:00.5Z", time.Date(2026, 10, 1, 12, 0, 0, 500000000, time.UTC)},
	}
	for _, tt := range tests {
		got, err := parseInvalidityDate(tt.in)
		if err != nil || !got.Equal(tt.want) {
			t.Errorf("parseInvalidityDate(%q) = %v, %v, want %v", tt.in, got, err, tt.want)
		}
	}
	for _, in := range []string{"", "yesterday", "2026-13-01", "2026-10-01 12:00", "2026-10-01T12:00"} {
		if got, err := parseInvalidityDate(in); err == nil {
			t.Errorf("parseInvalidityDate(%q) = %v, want an error", in, got)
		}
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
