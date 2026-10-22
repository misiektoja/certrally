package cmpfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	est "github.com/misiektoja/go-pki-est"
	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/trace"
)

// estFixtures returns a PKCS#10 request, a certs-only message and CSR attributes as DER.
func estFixtures(t *testing.T) (csr, certsOnly, csrAttrs []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if certsOnly, err = pkcs7.DegenerateCertificate(cert); err != nil {
		t.Fatal(err)
	}
	csrAttrs, err = est.CSRAttrs{OIDs: []asn1.ObjectIdentifier{{1, 2, 840, 113549, 1, 9, 7}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return csr, certsOnly, csrAttrs
}

// TestParseESTFiles checks that files holding an EST message decode with their content.
func TestParseESTFiles(t *testing.T) {
	csr, certsOnly, csrAttrs := estFixtures(t)
	tests := []struct {
		name    string
		data    []byte
		content string
	}{
		{"pkcs10 der", csr, trace.ContentPKCS10},
		{"pkcs10 pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), trace.ContentPKCS10},
		{"pkcs10 base64 body", []byte(base64.StdEncoding.EncodeToString(csr)), trace.ContentPKCS10},
		{"certs-only der", certsOnly, trace.ContentCertsOnly},
		{"certs-only pem", pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: certsOnly}), trace.ContentCertsOnly},
		{"certs-only other pem type", pem.EncodeToMemory(&pem.Block{Type: "MESSAGE", Bytes: certsOnly}), trace.ContentCertsOnly},
		{"csrattrs der", csrAttrs, trace.ContentCSRAttrs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := Parse("f", tt.data)
			if err != nil {
				t.Fatal(err)
			}
			m := msgs[0]
			if len(msgs) != 1 || m.Msg != nil || m.EST == nil || m.EST.Content != tt.content {
				t.Fatalf("got %d messages, first %+v", len(msgs), m)
			}
			if m.Request != (tt.content == trace.ContentPKCS10) || m.EST.Kind != map[bool]string{true: "request", false: "response"}[m.Request] {
				t.Errorf("request %v, kind %q", m.Request, m.EST.Kind)
			}
			if m.Run != 0 || len(m.DER) == 0 || m.EST.Size != len(m.DER) {
				t.Errorf("run %d, %d bytes of DER, size %d", m.Run, len(m.DER), m.EST.Size)
			}
		})
	}
}

// TestParseESTErrors checks EST-looking input that is not an EST message.
func TestParseESTErrors(t *testing.T) {
	csr, _, _ := estFixtures(t)
	tests := []struct {
		name, data, want string
	}{
		{"pem type mismatch", string(pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: csr})), "f: PEM block 1 (PKCS7) does not decode"},
		{"sequence of integers", string([]byte{0x30, 0x03, 0x02, 0x01, 0x01}), "and not a PKCS#10 request"},
		{"empty sequence", string([]byte{0x30, 0x00}), "and not a PKCS#10 request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse("f", []byte(tt.data)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %v, want %q", err, tt.want)
			}
		})
	}
}

// TestParseESTCapture checks that an EST run keeps every request and response, also without a
// body, and skips connections and failures.
func TestParseESTCapture(t *testing.T) {
	csr, certsOnly, _ := estFixtures(t)
	retry := 5
	data := captureLines(t,
		map[string]any{"kind": "start", "format": 1, "protocol": "est", "server": "https://est.example.com"},
		map[string]any{"kind": "connect", "tls": map[string]any{"version": "TLS 1.3"}},
		map[string]any{"kind": "request", "method": "POST", "path": "/.well-known/est/simpleenroll", "operation": "simpleenroll",
			"content": trace.ContentPKCS10, "der": csr},
		map[string]any{"kind": "response", "httpStatus": 202, "operation": "simpleenroll", "retryAfter": retry},
		map[string]any{"kind": "request", "method": "POST", "path": "/.well-known/est/simpleenroll", "operation": "simpleenroll",
			"content": trace.ContentPKCS10, "der": csr},
		map[string]any{"kind": "response", "httpStatus": 200, "operation": "simpleenroll", "content": trace.ContentCertsOnly,
			"certificates": 1, "der": certsOnly},
		map[string]any{"kind": "failure", "problem": "connection reset"},
	)
	msgs, err := Parse("run.jsonl", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 4 {
		t.Fatalf("got %d messages, want the two requests and two responses", len(msgs))
	}
	pending := msgs[1]
	if pending.Source != "run.jsonl:4" || pending.Request || pending.Server != "https://est.example.com" || pending.Run != 1 {
		t.Errorf("pending response %+v", pending)
	}
	if pending.EST.HTTPStatus != 202 || pending.EST.RetryAfter == nil || *pending.EST.RetryAfter != retry || len(pending.DER) != 0 {
		t.Errorf("pending record %+v", pending.EST)
	}
	if issued := msgs[3]; issued.EST.Certificates != 1 || string(issued.DER) != string(certsOnly) || issued.Msg != nil {
		t.Errorf("issued response %+v", issued)
	}
	if !msgs[0].Request || msgs[0].EST.Operation != "simpleenroll" {
		t.Errorf("request %+v", msgs[0])
	}
}
