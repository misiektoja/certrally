package estca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"testing"

	"github.com/misiektoja/go-composite-mldsa/compositex509"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
)

// request returns a request for a new key of keyType with a subject and a DNS name.
func request(t *testing.T, keyType string) *x509.CertificateRequest {
	t.Helper()
	key, err := keys.Generate(keyType)
	if err != nil {
		t.Fatal(err)
	}
	san, err := dn.SubjectAltName([]string{"dns:device-42.example.com"}, false)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-42"}, ExtraExtensions: []pkix.Extension{san}}
	der, err := compositex509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestEnroll checks that an issued certificate carries the request's names and verifies.
func TestEnroll(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, keyType := range []string{"ecdsa-p256", "ml-dsa-65", "mldsa65-ecdsa-p256-sha512"} {
		cert, err := ca.Enroll(context.Background(), request(t, keyType), "", nil)
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		if cert.Subject.CommonName != "device-42" || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "device-42.example.com" {
			t.Errorf("%s: issued %v %v", keyType, cert.Subject, cert.DNSNames)
		}
		if err := ca.Verify(cert); err != nil {
			t.Errorf("%s: %v", keyType, err)
		}
	}
}

// TestServerKeyGen checks that the generated key has the type of the request key and matches the
// certificate.
func TestServerKeyGen(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, keyType := range []string{"ecdsa-p384", "ed25519", "ml-dsa-44"} {
		cert, der, err := ca.ServerKeyGen(context.Background(), request(t, keyType), "", nil)
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		key, err := keys.Parse(der)
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		pub, err := keys.CertificateKey(cert)
		if err != nil {
			t.Fatal(err)
		}
		if got := keys.Describe(keys.Public(key)); got != keys.Describe(pub) {
			t.Errorf("%s: key %s, certificate %s", keyType, got, keys.Describe(pub))
		}
		if !keys.Public(key).(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
			t.Errorf("%s: the key does not belong to the certificate", keyType)
		}
	}
}

// TestRetryAfter checks that each new key waits once.
func TestRetryAfter(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ca.RetryAfter = 7
	csr := request(t, "ecdsa-p256")
	_, err = ca.Enroll(context.Background(), csr, "", nil)
	var estErr *Error
	if !errors.As(err, &estErr) || estErr.StatusCode() != http.StatusAccepted || estErr.RetryAfter() != 7 {
		t.Fatalf("first request: %v", err)
	}
	if _, err := ca.Enroll(context.Background(), csr, "", nil); err != nil {
		t.Errorf("second request: %v", err)
	}
}

// TestServerCertificate checks that the server certificate verifies for its hosts against the CA.
func TestServerCertificate(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := ca.ServerCertificate([]string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	for _, host := range []string{"localhost", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
}
