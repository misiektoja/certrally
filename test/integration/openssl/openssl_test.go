//go:build integration

// Package openssl runs certrally against the CMP mock server of OpenSSL, started as openssl cmp -port.
package openssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/test/integration/internal/itest"
)

const (
	// secretRef names the shared secret to the mock server.
	secretRef = "certrally"
	// rspName is the common name of the certificate that the mock server returns for every request.
	rspName    = "certrally-integration-rsp"
	rspSubject = "CN=" + rspName
)

// TestMockServer sends every CMP request type to one mock server. The server answers each
// enrollment with the same certificate, so every request certifies the key of that certificate.
// The mock server accepts only PasswordBasedMac, so shared-secret requests use --mac pbm.
func TestMockServer(t *testing.T) {
	requireOpenSSL(t)
	c := itest.New(t)
	writePKI(t, c)
	url := startMockServer(t, c.Dir)

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"ir", func(t *testing.T) {
			c.Expect(t, 0, "enroll", "--server", url, "--ref", secretRef, "--secret-file", "secret.txt", "--mac", "pbm",
				"--subject", rspSubject, "--new-key", "rsp.key", "--ca-cert", "ca.pem", "--cert-out", "ir.pem", "--capture", "cmp.jsonl")
			c.CheckIssued(t, "ir.pem", "ca.pem", "rsp.key")
		}},
		{"ir-pbmac1", func(t *testing.T) {
			c.ExpectOutput(t, 3, "Try --mac pbm", "enroll", "--server", url, "--ref", secretRef, "--secret-file", "secret.txt",
				"--subject", rspSubject, "--new-key", "rsp.key", "--ca-cert", "ca.pem", "--cert-out", "ir-pbmac1.pem", "--capture", "cmp.jsonl")
		}},
		{"cr", func(t *testing.T) {
			c.Expect(t, 0, "enroll", "--server", url, "--type", "cr", "--cert", "ir.pem", "--key", "rsp.key",
				"--subject", rspSubject, "--new-key", "rsp.key", "--ca-cert", "ca.pem", "--cert-out", "cr.pem", "--capture", "cmp.jsonl")
			c.CheckIssued(t, "cr.pem", "ca.pem", "rsp.key")
		}},
		{"kur", func(t *testing.T) {
			c.Expect(t, 0, "enroll", "--server", url, "--type", "kur", "--cert", "ir.pem", "--key", "rsp.key",
				"--new-key", "rsp.key", "--ca-cert", "ca.pem", "--cert-out", "kur.pem", "--capture", "cmp.jsonl")
			c.CheckIssued(t, "kur.pem", "ca.pem", "rsp.key")
		}},
		// The kup carries only the server certificate, so the new certificate cannot be verified.
		{"kur-without-ca-cert", func(t *testing.T) {
			c.ExpectOutput(t, 4, "Pass it with --ca-cert", "enroll", "--server", url, "--type", "kur", "--cert", "ir.pem", "--key", "rsp.key",
				"--new-key", "rsp.key", "--cert-out", "kur-without-ca-cert.pem", "--capture", "cmp.jsonl")
		}},
		{"p10cr", func(t *testing.T) {
			c.Expect(t, 0, "enroll", "--server", url, "--type", "p10cr", "--ref", secretRef, "--secret-file", "secret.txt", "--mac", "pbm",
				"--subject", rspSubject, "--new-key", "rsp.key", "--ca-cert", "ca.pem", "--cert-out", "p10cr.pem", "--capture", "cmp.jsonl")
			c.CheckIssued(t, "p10cr.pem", "ca.pem", "rsp.key")
		}},
		{"rr", func(t *testing.T) {
			c.Expect(t, 0, "revoke", "--server", url, "--cert", "ir.pem", "--key", "rsp.key", "--ca-cert", "ca.pem", "--yes",
				"--capture", "cmp.jsonl")
		}},
		{"inspect", func(t *testing.T) {
			c.Expect(t, 0, "inspect", "cmp.jsonl", "--ca-cert", "ca.pem", "--secret-file", "secret.txt")
		}},
		{"lint", func(t *testing.T) {
			c.Expect(t, 0, "lint", "cmp.jsonl", "--ca-cert", "ca.pem")
		}},
	}
	for _, step := range steps {
		// Each step uses the files that the steps before it wrote.
		if !t.Run(step.name, step.run) {
			t.FailNow()
		}
	}
}

// requireOpenSSL fails the test unless the openssl on PATH is OpenSSL 3.5 or newer, the oldest
// release that CI tests.
func requireOpenSSL(t *testing.T) {
	t.Helper()
	out, err := exec.Command("openssl", "version").Output()
	if err != nil {
		t.Fatalf("run openssl version: %v. Put OpenSSL 3.5 or newer on PATH", err)
	}
	t.Logf("%s", out)
	m := regexp.MustCompile(`^OpenSSL (\d+)\.(\d+)\.`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("openssl on PATH is not OpenSSL. Put OpenSSL 3.5 or newer on PATH")
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	if major < 3 || major == 3 && minor < 5 {
		t.Fatalf("openssl on PATH is OpenSSL %d.%d. Put OpenSSL 3.5 or newer on PATH", major, minor)
	}
}

// writePKI writes a CA certificate, the certificate the mock server signs with, the certificate it
// returns for every enrollment, their keys and the shared secret into the working directory.
func writePKI(t *testing.T, c *itest.Certrally) {
	t.Helper()
	caKey := newKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkix.Name{CommonName: "certrally integration CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	c.WriteFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	for _, leaf := range []struct{ name, cn string }{
		{"server", "certrally-integration-server"},
		{"rsp", rspName},
	} {
		key := newKey(t)
		pub, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		ski := sha256.Sum256(pub)
		template := &x509.Certificate{
			SerialNumber: serialNumber(t),
			Subject:      pkix.Name{CommonName: leaf.cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			SubjectKeyId: ski[:20],
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err := keys.MarshalPEM(key)
		if err != nil {
			t.Fatal(err)
		}
		c.WriteFile(t, leaf.name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		c.WriteFile(t, leaf.name+".key", keyPEM)
	}

	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	c.WriteFile(t, "secret.txt", []byte(hex.EncodeToString(secret)+"\n"))
}

// startMockServer starts the mock server on a free port and returns its URL. The server stops
// when the test ends, and its log is shown when the test failed.
func startMockServer(t *testing.T, dir string) string {
	t.Helper()
	port := freePort(t)
	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("openssl", "cmp", "-port", strconv.Itoa(port),
		"-srv_ref", secretRef, "-srv_secret", "file:secret.txt",
		"-srv_cert", "server.pem", "-srv_key", "server.key", "-srv_trusted", "ca.pem",
		"-rsp_cert", "rsp.pem", "-rsp_capubs", "ca.pem")
	cmd.Dir = dir
	// A path that cannot exist keeps a local openssl.cnf from changing how the server behaves.
	cmd.Env = append(os.Environ(), "OPENSSL_CONF=/dev/null/openssl.cnf")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the mock server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
		if t.Failed() {
			log, _ := os.ReadFile(logPath)
			t.Logf("mock server log:\n%s", log)
		}
	})

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			_ = conn.Close()
			return fmt.Sprintf("http://%s/pkix/", addr)
		}
	}
	t.Fatalf("the mock server did not listen on %s within 10 seconds", addr)
	return ""
}

// freePort returns a TCP port on the loopback address that is free at the time of the call.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newKey generates an ECDSA P-256 key.
func newKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// serialNumber returns a random 128-bit certificate serial number.
func serialNumber(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
