package cli

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCACerts checks cacerts and cmp genm cacerts with file and standard output.
func TestCACerts(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	caCert := readCert(t, ca.caFile)

	out := filepath.Join(t.TempDir(), "cas.pem")
	code, stdout, errOut := run(t, "cacerts", "--server", ca.url, "--ref", testRef, "--out", out)
	t.Log(errOut + stdout)
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	if got := readCert(t, out); !got.Equal(caCert) {
		t.Errorf("saved %s", got.Subject)
	}
	for _, want := range []string{"Received 1 CA certificate", "self-signed", "SHA-256", out} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report lacks %q:\n%s", want, stdout)
		}
	}

	code, stdout, errOut = run(t, "cmp", "genm", "cacerts", "--server", ca.url, "--ref", testRef, "--out", "-")
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	if block, rest := pem.Decode([]byte(stdout)); block == nil || len(rest) != 0 || !bytes.Equal(block.Bytes, caCert.Raw) {
		t.Errorf("standard output is not the CA certificate:\n%s", stdout)
	}
	if !strings.Contains(errOut, "Received 1 CA certificate") {
		t.Errorf("the report did not move to standard error:\n%s", errOut)
	}
}

// TestGenMSupport checks the template, root update and CRL support messages.
func TestGenMSupport(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	crlFile := filepath.Join(dir, "ca.crl")

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"template", []string{"template", "--cert-profile", "tls"}, []string{"Certificate request template", "Subject    CN=\n", "fill in", "ECDSA P-256"}},
		{"rootupdate", []string{"rootupdate", "--old-root", ca.caFile}, []string{"No root CA update is available"}},
		{"crl", []string{"crl", "--out", crlFile}, []string{"Received a CRL", "Signature    valid", "Revoked      0"}},
		{"crlupdate current", []string{"crlupdate", "--crl", crlFile}, []string{"No newer CRL is available"}},
		{"crlupdate issuer", []string{"crlupdate", "--crl-issuer", ca.caFile}, []string{"Received a CRL", "Signature    valid"}},
		{"raw", []string{"raw", "caCerts"}, []string{"The answer holds 1 item\n", "caCerts", "1.3.6.1.5.5.7.4.17"}},
		{"raw two info types", []string{"raw", "caCerts", "currentcrl"}, []string{"2 items", "caCerts", "currentCRL"}},
		{"raw unknown info type", []string{"raw", "1.2.3.4"}, []string{"unsupportedOIDs"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"cmp", "genm"}, tt.args...)
			args = append(args, "--server", ca.url, "--ref", testRef)
			code, out, errOut := run(t, args...)
			t.Log(errOut + out)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s", code, errOut)
			}
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("report lacks %q:\n%s", want, out)
				}
			}
		})
	}
	data, err := os.ReadFile(crlFile)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(data); block == nil || block.Type != "X509 CRL" {
		t.Errorf("saved CRL is not PEM:\n%s", data)
	}
}

// TestGenMFailures checks requests the server refuses and command lines refused locally.
func TestGenMFailures(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{"bad info type", []string{"raw", "1.x"}, exitLocal, "not an info type name"},
		{"no info type", []string{"raw"}, exitLocal, "requires at least 1 arg"},
		{"rootupdate without old root", []string{"rootupdate"}, exitLocal, "--old-root is required"},
		{"crlupdate without crl", []string{"crlupdate"}, exitLocal, "crl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"cmp", "genm"}, tt.args...)
			args = append(args, "--server", ca.url, "--ref", testRef)
			code, out, errOut := run(t, args...)
			t.Log(errOut + out)
			if code != tt.wantCode || !strings.Contains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.wantCode, tt.want, errOut)
			}
		})
	}
}

// TestParseInfoType checks info type names, dotted OIDs and their display names.
func TestParseInfoType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"cacerts", "1.3.6.1.5.5.7.4.17"},
		{"kemCiphertextInfo", "1.3.6.1.5.5.7.4.24"},
		{"1.2.3", "1.2.3"},
	}
	for _, tt := range tests {
		oid, err := parseInfoType(tt.in)
		if err != nil || oid.String() != tt.want {
			t.Errorf("parseInfoType(%q) = %v, %v", tt.in, oid, err)
		}
	}
	for _, bad := range []string{"", "1", "1.02", "1.-2", "nope"} {
		if _, err := parseInfoType(bad); err == nil {
			t.Errorf("parseInfoType(%q) succeeded", bad)
		}
	}
	if got := infoTypeName(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 20}); got != "rootCaCert" {
		t.Errorf("infoTypeName = %q", got)
	}
	if got := infoTypeName(asn1.ObjectIdentifier{1, 2, 3}); got != "1.2.3" {
		t.Errorf("infoTypeName = %q", got)
	}
}
