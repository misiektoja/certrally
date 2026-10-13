package pemfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testCert returns a throwaway self-signed certificate.
func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestReadCertificates checks PEM bundles, DER input and rejected content.
func TestReadCertificates(t *testing.T) {
	dir := t.TempDir()
	a, b := testCert(t, "a"), testCert(t, "b")
	files := map[string][]byte{
		"bundle.pem": append([]byte("subject=a\n"), EncodeCertificates([]*x509.Certificate{a, b})...),
		"one.der":    a.Raw,
		"key.pem":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}),
		"empty.pem":  nil,
		"broken.pem": []byte("-----BEGIN CERTIFICATE-----\nnot base64"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certs, err := ReadCertificates(filepath.Join(dir, "bundle.pem"))
	if err != nil || len(certs) != 2 || !certs[1].Equal(b) {
		t.Errorf("bundle: %d certificates, %v", len(certs), err)
	}
	certs, err = ReadCertificates(filepath.Join(dir, "one.der"))
	if err != nil || len(certs) != 1 || !certs[0].Equal(a) {
		t.Errorf("DER: %d certificates, %v", len(certs), err)
	}
	for _, name := range []string{"key.pem", "empty.pem", "broken.pem", "missing.pem"} {
		if _, err := ReadCertificates(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s: read, want an error", name)
		}
	}
}

// TestWrite checks permissions, the no-clobber rule and --force.
func TestWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.key")
	if err := CheckWritable(path, false); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("one"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, %v", info.Mode(), err)
	}
	if err := CheckWritable(path, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("CheckWritable on an existing file = %v", err)
	}
	if err := Write(path, []byte("two"), 0o600, false); err == nil {
		t.Error("Write replaced an existing file without overwrite")
	}
	if err := Write(path, []byte("three"), 0o600, true); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "three" {
		t.Errorf("content = %q", data)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	if err := CheckWritable(filepath.Join(path+".d", "x"), false); err == nil {
		t.Error("CheckWritable accepted a missing directory")
	}
}
