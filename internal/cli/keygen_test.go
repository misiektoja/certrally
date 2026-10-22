package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"

	"github.com/misiektoja/certrally/internal/keys"
)

// readPEM returns the single PEM block of type typ in a file.
func readPEM(t *testing.T, path, typ string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != typ || len(rest) != 0 {
		t.Fatalf("%s is not a single %s block", path, typ)
	}
	return block.Bytes
}

// TestKeygen checks the key, public key and request files for classical, ML-DSA and composite keys.
func TestKeygen(t *testing.T) {
	isolateColorEnv(t)
	composite := strings.ToLower(compositemldsa.Algorithms()[0].String())
	for _, keyType := range []string{"ecdsa-p384", "ed25519", "ml-dsa-87", composite} {
		t.Run(keyType, func(t *testing.T) {
			dir := t.TempDir()
			keyOut, pubOut, csrOut := filepath.Join(dir, "k.pem"), filepath.Join(dir, "pub.pem"), filepath.Join(dir, "req.csr")
			code, out, errOut := run(t, "keygen", "--key-type", keyType, "--out", keyOut, "--pub-out", pubOut,
				"--csr-out", csrOut, "--subject", "CN=device-42", "--san", "device-42.example.com")
			t.Log(out)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s", code, errOut)
			}
			info, err := os.Stat(keyOut)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("key file mode = %o, want 600", perm)
			}
			keyData, err := os.ReadFile(keyOut)
			if err != nil {
				t.Fatal(err)
			}
			key, err := keys.Parse(keyData)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := compositex509.ParsePKIXPublicKey(readPEM(t, pubOut, "PUBLIC KEY"))
			if err != nil {
				t.Fatal(err)
			}
			if k, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !k.Equal(pub) {
				t.Error("the public key does not match the private key")
			}
			csr, err := x509.ParseCertificateRequest(readPEM(t, csrOut, "CERTIFICATE REQUEST"))
			if err != nil {
				t.Fatal(err)
			}
			if err := compositex509.CheckCertificateRequestSignature(csr); err != nil {
				t.Errorf("request signature: %v", err)
			}
			if csr.Subject.String() != "CN=device-42" || len(csr.DNSNames) != 1 {
				t.Errorf("request names %s %v", csr.Subject, csr.DNSNames)
			}
			for _, want := range []string{"Key generated", keys.Describe(key.Public()), keyOut, csrOut} {
				if !strings.Contains(out, want) {
					t.Errorf("report lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestKeygenStdout checks that a key written to standard output moves the report to standard error.
func TestKeygenStdout(t *testing.T) {
	isolateColorEnv(t)
	code, out, errOut := run(t, "keygen", "--out", "-")
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	if _, err := keys.Parse([]byte(out)); err != nil {
		t.Errorf("standard output is not a key: %v", err)
	}
	if !errorContains(errOut, "ECDSA P-256") {
		t.Errorf("report:\n%s", errOut)
	}
}

// TestKeygenList checks that --list prints one key type per line.
func TestKeygenList(t *testing.T) {
	isolateColorEnv(t)
	code, out, _ := run(t, "keygen", "--list")
	if code != exitOK || strings.TrimSpace(out) != strings.Join(keys.TypeNames(), "\n") {
		t.Errorf("exited with %d:\n%s", code, out)
	}
}

// TestKeygenUsage checks that invalid command lines fail with status 1 and keep existing files.
func TestKeygenUsage(t *testing.T) {
	isolateColorEnv(t)
	dir := t.TempDir()
	existing, key := filepath.Join(dir, "existing.pem"), filepath.Join(dir, "k.pem")
	writeFile(t, existing, []byte("keep"))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no output", nil, "--out is required"},
		{"existing output", []string{"--out", existing}, "already exists"},
		{"existing request", []string{"--out", key, "--csr-out", existing, "--subject", "CN=a"}, "already exists"},
		{"subject without request", []string{"--out", key, "--subject", "CN=a"}, "need --csr-out"},
		{"request without names", []string{"--out", key, "--csr-out", filepath.Join(dir, "r.csr")}, "--subject or --san"},
		{"two standard outputs", []string{"--out", "-", "--pub-out", "-"}, "only one output"},
		{"bad key type", []string{"--out", key, "--key-type", "dsa"}, "unknown key type"},
		{"bad subject", []string{"--out", key, "--csr-out", filepath.Join(dir, "r.csr"), "--subject", "XX=1"}, "--subject"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, append([]string{"keygen"}, tt.args...)...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want 1 and %q in:\n%s", code, tt.want, errOut)
			}
		})
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep" {
		t.Error("an existing file was overwritten")
	}
	if _, err := os.Stat(key); err == nil {
		t.Error("a key was written by a failed command")
	}
}
