package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/certrally/internal/pemfile"
)

// TestStrictProfile checks that the go-pki-cmp example CA meets the strict profile for every
// command, so a deviation the checks report points at a real CA problem.
func TestStrictProfile(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca, "--subject", "CN=device-42")
	dir := t.TempDir()
	crlFile := filepath.Join(dir, "ca.crl")

	tests := []struct {
		name string
		args []string
	}{
		{"ir", []string{"enroll", "--ref", testRef, "--cert-out", filepath.Join(dir, "ir.pem"), "--key-out", filepath.Join(dir, "ir.key")}},
		{"kur", []string{"enroll", "--type", "kur", "--cert", certFile, "--key", keyFile,
			"--cert-out", filepath.Join(dir, "kur.pem"), "--key-out", filepath.Join(dir, "kur.key")}},
		{"cacerts", []string{"cacerts", "--ref", testRef}},
		{"template", []string{"cmp", "genm", "template", "--ref", testRef}},
		{"crl", []string{"cmp", "genm", "crl", "--ref", testRef, "--out", crlFile}},
		{"raw", []string{"cmp", "genm", "raw", "caCerts", "--ref", testRef}},
		{"ping", []string{"ping"}},
		{"revoke", []string{"revoke", "--cert", certFile, "--key", keyFile, "--yes"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(slices.Clone(tt.args), "--server", ca.url, "--profile", "strict", "--ca-cert", ca.caFile)
			code, doc := runJSON(t, args...)
			if code != exitOK || doc["warnings"] != nil || doc["profile"] != "strict" {
				t.Errorf("exited with %d: %v", code, doc)
			}
		})
	}
}

// withoutExtraCerts returns a PKIMessage without its extraCerts field. It returns der unchanged
// when der is not a PKIMessage.
func withoutExtraCerts(der []byte) []byte {
	input := cryptobyte.String(der)
	var seq, header, body, protection cryptobyte.String
	var protectionPresent bool
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&header, cbasn1.SEQUENCE) ||
		!seq.ReadAnyASN1Element(&body, nil) ||
		!seq.ReadOptionalASN1(&protection, &protectionPresent, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return der
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(header)
		b.AddBytes(body)
		if protectionPresent {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(protection) })
		}
	})
	return b.BytesOrPanic()
}

// stripExtraCerts serves a proxy in front of target that removes extraCerts from every response.
// extraCerts are outside the protection, so the responses still verify.
func stripExtraCerts(t *testing.T, target string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Post(target, r.Header.Get("Content-Type"), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, bytes.NewReader(withoutExtraCerts(body)))
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/cmp"
}

// intermediateCA issues certificates from an intermediate CA under the example CA, so an ip
// without extraCerts lacks the chain of the new certificate.
type intermediateCA struct {
	*mockserver.MockCA
	cert *x509.Certificate
	key  crypto.Signer
}

// newIntermediateCA creates an intermediate CA under m.
func newIntermediateCA(t *testing.T, m *mockserver.MockCA) intermediateCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := server.GenerateSerial()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.Cert(), key.Public(), m.Key())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return intermediateCA{MockCA: m, cert: cert, key: key}
}

// IssueCertificate signs the template with the intermediate CA.
func (c intermediateCA) IssueCertificate(_ context.Context, _ server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, tmpl.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &server.Response{Certificate: cert}, nil
}

// TestProfileRootIssuer checks that a certificate from a root CA needs no chain in extraCerts,
// because RFC 9483 leaves self-signed certificates out.
func TestProfileRootIssuer(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	for _, trust := range [][]string{nil, {"--ca-cert", ca.caFile}} {
		args := append([]string{"enroll", "--server", stripExtraCerts(t, ca.url), "--ref", testRef, "--profile", "strict",
			"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"), "--force"}, trust...)
		code, doc := runJSON(t, args...)
		// Without --ca-cert the run trusts the first response over plain HTTP, which warns.
		var want []any
		if trust == nil {
			want = []any{plainHTTPTrustWarning}
		}
		warnings, _ := doc["warnings"].([]any)
		if code != exitOK || !slices.Equal(warnings, want) {
			t.Errorf("%q exited with %d: %v", trust, code, doc)
		}
	}
}

// TestProfileDeviation checks how each profile treats an ip without the chain of the new certificate.
func TestProfileDeviation(t *testing.T) {
	const deviation = "The ip response carries no extraCerts, so the chain of the new certificate is missing (RFC 9483 section 3.3)."
	useSecret(t, testSecret)
	var issuing intermediateCA
	ca := startCA(t, func(m *mockserver.MockCA) server.CA {
		issuing = newIntermediateCA(t, m)
		return issuing
	})
	dir := t.TempDir()
	// The client gets the intermediate CA from --ca-cert, so the new certificate verifies.
	chainFile := filepath.Join(dir, "chain.pem")
	writeFile(t, chainFile, pemfile.EncodeCertificates([]*x509.Certificate{issuing.cert, issuing.Cert()}))
	proxy := stripExtraCerts(t, ca.url)
	enroll := func(name string, extra ...string) []string {
		return append([]string{"enroll", "--server", proxy, "--ref", testRef, "--ca-cert", chainFile,
			"--cert-out", filepath.Join(dir, name+".pem"), "--key-out", filepath.Join(dir, name+".key")}, extra...)
	}

	t.Run("compatible text", func(t *testing.T) {
		code, _, errOut := run(t, enroll("text")...)
		if code != exitOK || !errorContains(errOut, deviation) {
			t.Errorf("exited with %d:\n%s", code, errOut)
		}
	})
	t.Run("compatible json", func(t *testing.T) {
		code, doc := runJSON(t, enroll("json")...)
		if code != exitOK || get(doc, "warnings.0") != deviation || doc["profile"] != "compatible" {
			t.Errorf("exited with %d: %v", code, doc)
		}
	})
	t.Run("strict", func(t *testing.T) {
		code, doc := runJSON(t, enroll("strict", "--profile", "strict")...)
		if code != exitProfile || get(doc, "error.title") != "The response breaks the strict profile" ||
			get(doc, "error.message") != deviation || doc["warnings"] != nil {
			t.Errorf("exited with %d: %v", code, doc)
		}
		// The certificate is not accepted, so it is neither confirmed nor saved.
		if got := exchangeBodies(doc); got != "ir ip" {
			t.Errorf("exchange bodies = %q", got)
		}
		if _, err := os.Stat(filepath.Join(dir, "strict.pem")); !os.IsNotExist(err) {
			t.Errorf("certificate saved: %v", err)
		}
	})
	t.Run("strict text", func(t *testing.T) {
		code, _, errOut := run(t, enroll("strict-text", "--profile", "strict")...)
		if code != exitProfile || !errorContains(errOut, "--profile compatible") {
			t.Errorf("exited with %d:\n%s", code, errOut)
		}
	})
}

// copySenderKID serves a proxy in front of target that answers a signed request like a CA that copies
// the senderKID of the request into its signed responses. key and cert sign each response again, so it
// still verifies.
func copySenderKID(t *testing.T, target string, key crypto.Signer, cert *x509.Certificate) string {
	t.Helper()
	// The signature keeps the given senderKID when the certificate has no subject key identifier.
	// extraCerts still carry the certificate as issued.
	signer := *cert
	signer.SubjectKeyId = nil
	creds, err := pkicmp.NewSignatureCredentials(key, &signer)
	if err != nil {
		t.Fatal(err)
	}
	signed := func(m *pkicmp.PKIMessage) bool {
		alg := m.Header.ProtectionAlg
		return alg != nil && !alg.Algorithm.Equal(oidPBM) && !alg.Algorithm.Equal(oidPBMAC1)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := pkicmp.ParsePKIMessage(der)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := http.Post(target, r.Header.Get("Content-Type"), bytes.NewReader(der))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if msg, err := pkicmp.ParsePKIMessage(body); err == nil && signed(req) && signed(msg) {
			msg.Header.SenderKID = req.Header.SenderKID
			if err := creds.Protect(msg); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if body, err = msg.MarshalBinary(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/cmp"
}

// TestProfileCopiedSenderKID checks a CA that copies the senderKID of a signed request into its signed
// responses. The compatible profile accepts them with a warning and the strict profile stops. inspect
// still finds the signer and lint names the rule.
func TestProfileCopiedSenderKID(t *testing.T) {
	const deviation = "response has a senderKID that is not the subject key identifier of its sender's certificate (RFC 9483 section 3.1)."
	useSecret(t, testSecret)
	var mock *mockserver.MockCA
	ca := startCA(t, func(m *mockserver.MockCA) server.CA {
		mock = m
		return m
	})
	certFile, keyFile := enrollIR(t, ca)
	proxy := copySenderKID(t, ca.url, mock.Key(), mock.Cert())
	dir := t.TempDir()
	capture := filepath.Join(dir, "cr.jsonl")
	enroll := func(name string, extra ...string) []string {
		return append([]string{"enroll", "--server", proxy, "--type", "cr", "--subject", "CN=device-42",
			"--cert", certFile, "--key", keyFile, "--ca-cert", ca.caFile,
			"--cert-out", filepath.Join(dir, name+".pem"), "--key-out", filepath.Join(dir, name+".key")}, extra...)
	}

	t.Run("compatible", func(t *testing.T) {
		code, doc := runJSON(t, enroll("compatible", "--capture", capture)...)
		if code != exitOK || get(doc, "warnings.0") != "The cp "+deviation || get(doc, "warnings.1") != "The pkiconf "+deviation {
			t.Errorf("exited with %d: %v", code, doc)
		}
	})
	t.Run("strict", func(t *testing.T) {
		code, doc := runJSON(t, enroll("strict", "--profile", "strict")...)
		hint, _ := get(doc, "error.hint").(string)
		if code != exitProfile || get(doc, "error.message") != "The cp "+deviation || !strings.Contains(hint, "--profile compatible") {
			t.Errorf("exited with %d: %v", code, doc)
		}
	})
	t.Run("inspect", func(t *testing.T) {
		code, doc := runJSON(t, "inspect", capture, "--ca-cert", ca.caFile)
		// Messages 1 and 3 are the cp and the pkiconf.
		for _, i := range []string{"1", "3"} {
			p := "result.messages." + i + ".protection"
			if code != exitOK || get(doc, p+".check") != "valid" || get(doc, p+".trusted") != true {
				t.Errorf("exited with %d, message %s: %v", code, i, get(doc, p))
			}
		}
	})
	t.Run("lint", func(t *testing.T) {
		code, out, errOut := run(t, "lint", capture)
		out += errOut
		if code != exitProfile || !strings.Contains(out, "The cp "+deviation) || strings.Contains(out, "section 3.3") {
			t.Errorf("exited with %d:\n%s", code, out)
		}
	})
}

// badRequest is a rejection without a reason the client could act on.
var badRequest = pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadRequest}

// rejectingServer answers every request with an unprotected rejection with status whose senderNonce is
// too short.
func rejectingServer(t *testing.T, status pkicmp.PKIStatusInfo) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := pkicmp.ParsePKIMessage(der)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := pkicmp.NewPKIMessage(pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: status}), pkicmp.MessageOptions{
			Sender:        pkicmp.NewDirectoryName(pkix.Name{CommonName: "Test CA"}),
			Recipient:     req.Header.Sender,
			TransactionID: req.Header.TransactionID,
			SenderNonce:   make([]byte, 8),
			RecipNonce:    req.Header.SenderNonce,
		})
		out, err := resp.MarshalBinary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pkixcmp")
		_, _ = w.Write(out)
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/cmp"
}

// TestProfileRejection checks that a strict session reports a CA rejection with the rules it
// breaks as warnings, because the reason the CA gives matters more.
func TestProfileRejection(t *testing.T) {
	useSecret(t, testSecret)
	code, doc := runJSON(t, "cacerts", "--server", rejectingServer(t, badRequest), "--ref", testRef, "--profile", "strict")
	want := "The error response has a senderNonce of 64 bits instead of at least 128 (RFC 9483 section 3.5)."
	if code != exitRejected || get(doc, "error.status") != "rejection" || get(doc, "warnings.0") != want {
		t.Errorf("exited with %d: %v", code, doc)
	}
}

// TestProfileUsage checks that an unknown profile is a usage error.
func TestProfileUsage(t *testing.T) {
	isolateColorEnv(t)
	code, _, errOut := run(t, "ping", "--server", "http://ca.test/cmp", "--profile", "lenient")
	if code != exitLocal || !errorContains(errOut, "--profile") {
		t.Errorf("exited with %d:\n%s", code, errOut)
	}
}
