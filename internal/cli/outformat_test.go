package cli

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/keys"
)

// readDER returns the content of a file after checking that it is not PEM.
func readDER(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(data, []byte("-----")) {
		t.Fatalf("%s is PEM, want DER", path)
	}
	return data
}

// certificatesInPKCS7 returns the certificates of a DER PKCS#7 file.
func certificatesInPKCS7(t *testing.T, data []byte) []*x509.Certificate {
	t.Helper()
	p7, err := pkcs7.Parse(data)
	if err != nil {
		t.Fatalf("parse PKCS#7: %v", err)
	}
	return p7.Certificates
}

// checkDERPair checks that certPath holds a DER certificate for the PKCS#8 DER key in keyPath.
func checkDERPair(t *testing.T, certPath, keyPath string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(readDER(t, certPath))
	if err != nil {
		t.Fatalf("%s: %v", certPath, err)
	}
	key, err := keys.Parse(readDER(t, keyPath))
	if err != nil {
		t.Fatalf("%s: %v", keyPath, err)
	}
	if !keys.Public(key).(interface{ Equal(crypto.PublicKey) bool }).Equal(cert.PublicKey) {
		t.Errorf("%s does not belong to %s", keyPath, certPath)
	}
	return cert
}

// TestOutFormatDERCMP checks --out-format der on enroll, cacerts and cmp genm crl: DER
// certificates and keys and PKCS#7 for several certificates.
func TestOutFormatDERCMP(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	caCert := readCert(t, ca.caFile)
	dir := t.TempDir()
	certOut, keyOut, chainOut := filepath.Join(dir, "cert.der"), filepath.Join(dir, "key.der"), filepath.Join(dir, "chain.p7b")
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--out-format", "der",
		"--cert-out", certOut, "--key-out", keyOut, "--chain-out", chainOut)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	checkDERPair(t, certOut, keyOut)
	if chain := certificatesInPKCS7(t, readDER(t, chainOut)); len(chain) != 1 || !chain[0].Equal(caCert) {
		t.Errorf("the chain holds %d certificates, want the CA certificate", len(chain))
	}

	t.Run("cacerts", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "cas.p7b")
		code, _, errOut := run(t, "cacerts", "--server", ca.url, "--ref", testRef, "--out", out, "--out-format", "der")
		if code != exitOK {
			t.Fatalf("exited with %d:\n%s", code, errOut)
		}
		if certs := certificatesInPKCS7(t, readDER(t, out)); len(certs) != 1 || !certs[0].Equal(caCert) {
			t.Errorf("saved %d certificates, want the CA certificate", len(certs))
		}
	})
	t.Run("cacerts on standard output", func(t *testing.T) {
		code, stdout, errOut := run(t, "cacerts", "--server", ca.url, "--ref", testRef, "--out", "-", "--out-format", "der")
		if code != exitOK {
			t.Fatalf("exited with %d:\n%s", code, errOut)
		}
		if certs := certificatesInPKCS7(t, []byte(stdout)); len(certs) != 1 || !certs[0].Equal(caCert) {
			t.Errorf("standard output holds %d certificates, want the CA certificate", len(certs))
		}
	})
	t.Run("crl", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "ca.crl")
		code, _, errOut := run(t, "cmp", "genm", "crl", "--server", ca.url, "--ref", testRef, "--out", out, "--out-format", "der")
		if code != exitOK {
			t.Fatalf("exited with %d:\n%s", code, errOut)
		}
		if _, err := x509.ParseRevocationList(readDER(t, out)); err != nil {
			t.Errorf("%s: %v", out, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--out-format", "pkcs12",
			"--cert-out", filepath.Join(t.TempDir(), "cert.p12"), "--key-out", filepath.Join(t.TempDir(), "key.p12"))
		if code != exitLocal || !errorContains(errOut, "invalid --out-format") {
			t.Errorf("exited with %d, want 1 and invalid --out-format in:\n%s", code, errOut)
		}
	})
}

// TestOutFormatPoll checks that poll writes the format of the enroll run unless --out-format
// replaces it.
func TestOutFormatPoll(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	dir := t.TempDir()
	captureFile := filepath.Join(dir, "run.jsonl")
	for _, tt := range []struct {
		name     string
		pollArgs []string
		der      bool
	}{
		{"inherited", nil, true},
		{"replaced", []string{"--out-format", "pem"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			certOut, keyOut := filepath.Join(dir, tt.name+".crt"), filepath.Join(dir, tt.name+".key")
			code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=device-42",
				"--out-format", "der", "--cert-out", certOut, "--key-out", keyOut, "--poll-later", "--capture", captureFile)
			if code != exitOK {
				t.Fatalf("enroll exited with %d:\n%s", code, errOut)
			}
			args := append([]string{"poll", "--transaction-id", transactionIDIn(t, out), "--capture", captureFile}, tt.pollArgs...)
			if code, _, errOut := run(t, args...); code != exitOK {
				t.Fatalf("poll exited with %d:\n%s", code, errOut)
			}
			if tt.der {
				checkDERPair(t, certOut, keyOut)
			} else if readCert(t, certOut).Subject.CommonName != "device-42" {
				t.Error("the PEM certificate has another subject")
			}
		})
	}
}

// TestOutFormatDEREST checks --out-format der on est enroll, est serverkeygen and est cacerts.
func TestOutFormatDEREST(t *testing.T) {
	usePassword(t, estTestPassword)
	srv := startESTServer(t, nil, nil, nil)
	for _, command := range []string{"enroll", "serverkeygen"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			certOut, keyOut := filepath.Join(dir, "cert.der"), filepath.Join(dir, "key.der")
			code, _, errOut := run(t, srv.args(command, "--user", estTestUser, "--subject", "CN=dev-1", "--out-format", "der",
				"--cert-out", certOut, "--key-out", keyOut)...)
			if code != exitOK {
				t.Fatalf("est %s exited with %d:\n%s", command, code, errOut)
			}
			if cert := checkDERPair(t, certOut, keyOut); cert.Subject.CommonName != "dev-1" {
				t.Errorf("subject %s, want CN=dev-1", cert.Subject)
			}
		})
	}
	t.Run("cacerts", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "cas.p7b")
		code, _, errOut := run(t, srv.args("cacerts", "--out", out, "--out-format", "der")...)
		if code != exitOK {
			t.Fatalf("exited with %d:\n%s", code, errOut)
		}
		if certs := certificatesInPKCS7(t, readDER(t, out)); len(certs) != 1 || !certs[0].Equal(srv.ca.Certificate()) {
			t.Errorf("saved %d certificates, want the CA certificate", len(certs))
		}
	})
}

// TestOutFormatDERKeygen checks keygen --out-format der for the key, public key and request files
// and on standard output.
func TestOutFormatDERKeygen(t *testing.T) {
	isolateColorEnv(t)
	dir := t.TempDir()
	keyOut, pubOut, csrOut := filepath.Join(dir, "key.der"), filepath.Join(dir, "pub.der"), filepath.Join(dir, "req.der")
	code, _, errOut := run(t, "keygen", "--out-format", "der", "--out", keyOut, "--pub-out", pubOut,
		"--csr-out", csrOut, "--subject", "CN=device-42")
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	key, err := keys.Parse(readDER(t, keyOut))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(readDER(t, pubOut))
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Public(key).(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
		t.Error("the public key file does not match the key")
	}
	csr, err := x509.ParseCertificateRequest(readDER(t, csrOut))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "device-42" || csr.CheckSignature() != nil {
		t.Errorf("request subject %s, signature %v", csr.Subject, csr.CheckSignature())
	}

	t.Run("standard output", func(t *testing.T) {
		code, stdout, errOut := run(t, "keygen", "--out-format", "der", "--out", "-")
		if code != exitOK {
			t.Fatalf("exited with %d:\n%s", code, errOut)
		}
		if bytes.HasPrefix([]byte(stdout), []byte("-----")) {
			t.Fatal("standard output is PEM, want DER")
		}
		if _, err := keys.Parse([]byte(stdout)); err != nil {
			t.Errorf("standard output: %v", err)
		}
	})
}
