// Package estca is an EST test CA that keeps its key and everything it issues in memory. It backs
// certrally est mock and the tests of the EST commands.
package estca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	est "github.com/misiektoja/go-pki-est"

	"github.com/misiektoja/certrally/internal/keys"
)

// validity is how long issued certificates are valid.
const validity = 365 * 24 * time.Hour

// OIDs of the CSR attributes the CA asks for.
var (
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidECPublicKey       = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256              = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// CA implements est.CA with a self-signed ECDSA P-256 root that signs every certificate.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate

	// RetryAfter, when positive, answers the first request for each new key with 202 Accepted and
	// this Retry-After value in seconds, so that clients can test waiting.
	RetryAfter int

	mu sync.Mutex
	// seen holds the SHA-256 hashes of the keys that already waited once.
	seen map[[32]byte]bool
}

// New creates a CA with a new key.
func New() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "certrally EST Mock CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(10 * validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{key: key, cert: cert, seen: map[[32]byte]bool{}}, nil
}

// Certificate returns the CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// ServerCertificate returns a TLS certificate for the given host names and IP addresses, signed by
// the CA, so that clients that trust the CA certificate also trust the server.
func (ca *CA) ServerCertificate(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "certrally EST Mock Server"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}, nil
}

// Verify reports whether cert was issued by the CA and is valid now.
func (ca *CA) Verify(cert *x509.Certificate) error {
	if err := compositex509.CheckSignatureFrom(cert, ca.cert); err != nil {
		return err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("the certificate is not valid now")
	}
	return nil
}

// CACerts returns the CA certificate.
func (ca *CA) CACerts(context.Context, string, *http.Request) ([]*x509.Certificate, error) {
	return []*x509.Certificate{ca.cert}, nil
}

// CSRAttrs asks for a challenge password and an ECDSA P-256 key signed with SHA-256, as a CA
// that prescribes the key would.
func (ca *CA) CSRAttrs(context.Context, string, *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{
		OIDs: []asn1.ObjectIdentifier{oidChallengePassword, oidECDSAWithSHA256},
		Attributes: []est.Attribute{
			{Type: oidECPublicKey, Values: est.AttributeValueSET{oidP256}},
		},
	}, nil
}

// Enroll issues a certificate for the request.
func (ca *CA) Enroll(_ context.Context, csr *x509.CertificateRequest, _ string, _ *http.Request) (*x509.Certificate, error) {
	if err := ca.wait(csr); err != nil {
		return nil, err
	}
	return ca.issue(csr)
}

// Reenroll issues a new certificate for the request. The server has already checked that its
// subject and subjectAltName match the certificate being renewed.
func (ca *CA) Reenroll(_ context.Context, _ *x509.Certificate, csr *x509.CertificateRequest, _ string, _ *http.Request) (*x509.Certificate, error) {
	if err := ca.wait(csr); err != nil {
		return nil, err
	}
	return ca.issue(csr)
}

// ServerKeyGen generates a key of the type in the request and issues a certificate for it. It
// returns the key as unencrypted PKCS#8.
func (ca *CA) ServerKeyGen(_ context.Context, csr *x509.CertificateRequest, _ string, _ *http.Request) (*x509.Certificate, []byte, error) {
	if err := ca.wait(csr); err != nil {
		return nil, nil, err
	}
	key, err := keys.GenerateSigner(keyType(csr))
	if err != nil {
		return nil, nil, err
	}
	data, err := keys.MarshalPEM(key)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	cert, err := ca.certify(csr, key.Public())
	if err != nil {
		return nil, nil, err
	}
	return cert, block.Bytes, nil
}

// TPMEnroll is not offered.
func (ca *CA) TPMEnroll(context.Context, *x509.CertificateRequest, []*x509.Certificate, []byte, []byte, string, *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, &Error{Status: http.StatusNotImplemented, Message: "TPM enrollment is not offered"}
}

// wait asks the client to retry later the first time it sends a key, when RetryAfter is set.
func (ca *CA) wait(csr *x509.CertificateRequest) error {
	if ca.RetryAfter <= 0 {
		return nil
	}
	sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.seen[sum] {
		return nil
	}
	ca.seen[sum] = true
	return &Error{Status: http.StatusAccepted, Message: "the request is pending", Retry: ca.RetryAfter}
}

// issue certifies the key of the request.
func (ca *CA) issue(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	pub, err := compositex509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, &Error{Status: http.StatusBadRequest, Message: "the key of the request does not decode"}
	}
	return ca.certify(csr, pub)
}

// certify issues a certificate for pub with the subject and subjectAltName of the request.
func (ca *CA) certify(csr *x509.CertificateRequest, pub crypto.PublicKey) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		RawSubject:   csr.RawSubject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// clientAuth lets the certificate sign in to /simplereenroll.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}
	}
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// keyType returns the certrally key type of the request key, so that a generated key matches what
// the client asked for. It falls back to ECDSA P-256.
func keyType(csr *x509.CertificateRequest) string {
	pub, err := compositex509.ParsePKIXPublicKey(csr.RawSubjectPublicKeyInfo)
	if err != nil {
		return keys.DefaultType
	}
	var name string
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		name = "ecdsa-" + strings.ReplaceAll(k.Curve.Params().Name, "-", "")
	case *rsa.PublicKey:
		name = fmt.Sprintf("rsa-%d", k.N.BitLen())
	case ed25519.PublicKey:
		name = "ed25519"
	default:
		// The names of ML-DSA and composite ML-DSA keys are their key types.
		name = keys.Describe(pub)
	}
	if !slices.ContainsFunc(keys.SigningTypeNames(), func(t string) bool { return strings.EqualFold(t, name) }) {
		return keys.DefaultType
	}
	return name
}

// newSerial returns a random positive serial number of 128 bits.
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// Error is an EST error with an HTTP status and an optional Retry-After value. It implements
// est.Error.
type Error struct {
	Status  int
	Message string
	Retry   int
}

// StatusCode returns the HTTP status.
func (e *Error) StatusCode() int { return e.Status }

// Error returns the message.
func (e *Error) Error() string { return e.Message }

// RetryAfter returns the Retry-After value in seconds.
func (e *Error) RetryAfter() int { return e.Retry }
