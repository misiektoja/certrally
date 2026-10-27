package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

// enrollArgs returns an enroll command against ca that writes its files to a fresh directory.
func enrollArgs(t *testing.T, ca *testCA, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	return append([]string{
		"enroll", "--server", ca.url, "--ref", testRef,
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"),
	}, extra...)
}

// trustedFingerprints returns the sha256 values of the certificates the document reports as
// trusted on the first response.
func trustedFingerprints(doc map[string]any) []string {
	certs, _ := doc["trustedOnFirstResponse"].([]any)
	sums := make([]string, 0, len(certs))
	for _, c := range certs {
		cert, _ := c.(map[string]any)
		sums = append(sums, text(cert["sha256"]))
	}
	return sums
}

// TestTrustOnFirstResponse checks that a CMP command reports the certificates it trusted from the
// first response with their fingerprints, once each, warns when plain HTTP carried them and reports
// neither with --ca-cert.
func TestTrustOnFirstResponse(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	sum := sha256.Sum256(readCert(t, ca.caFile).Raw)

	code, doc := runJSON(t, enrollArgs(t, ca)...)
	if code != exitOK {
		t.Fatalf("enroll exited with %d: %v", code, doc["error"])
	}
	if got, want := trustedFingerprints(doc), []string{hex.EncodeToString(sum[:])}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("trustedOnFirstResponse lists %v, want %v", got, want)
	}
	if !hasWarning(doc, plainHTTPTrustWarning) {
		t.Errorf("the document does not warn about plain HTTP: %v", doc["warnings"])
	}

	code, out, errOut := run(t, enrollArgs(t, ca)...)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if !strings.Contains(out, "Trusted on first response") || !strings.Contains(out, hexBytes(sum[:])) {
		t.Errorf("the report does not list the trusted certificate with its fingerprint:\n%s", out)
	}
	if !strings.Contains(errOut, plainHTTPTrustWarning) {
		t.Errorf("the report does not warn about plain HTTP:\n%s", errOut)
	}

	code, doc = runJSON(t, enrollArgs(t, ca, "--ca-cert", ca.caFile)...)
	if code != exitOK {
		t.Fatalf("enroll --ca-cert exited with %d: %v", code, doc["error"])
	}
	if _, ok := doc["trustedOnFirstResponse"]; ok {
		t.Errorf("--ca-cert still reports certificates trusted on the first response: %v", doc["trustedOnFirstResponse"])
	}
	if hasWarning(doc, "plain HTTP") {
		t.Errorf("--ca-cert still warns about plain HTTP: %v", doc["warnings"])
	}
}

// TestTrustOnFirstResponseOverTLS checks that HTTPS reports the trusted certificates without the
// plain HTTP warning.
func TestTrustOnFirstResponseOverTLS(t *testing.T) {
	useSecret(t, testSecret)
	ca := startTLSCA(t, nil)
	code, doc := runJSON(t, "ping", "--server", ca.url, "--insecure")
	if code != exitOK {
		t.Fatalf("ping exited with %d: %v", code, doc["error"])
	}
	if got := trustedFingerprints(doc); len(got) != 1 {
		t.Errorf("trustedOnFirstResponse lists %v, want one certificate", got)
	}
	if hasWarning(doc, "plain HTTP") {
		t.Errorf("HTTPS warns about plain HTTP: %v", doc["warnings"])
	}
}
