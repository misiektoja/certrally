package cli

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
)

// Credentials the test CA accepts for MAC-protected requests.
const (
	testRef    = "my-device"
	testSecret = "test-shared-secret"
)

// testCA is a CMP server backed by the go-pki-cmp example CA.
type testCA struct {
	url      string
	caFile   string
	requests atomic.Int32
}

// startCA serves a mock CA over HTTP. wrap, when set, replaces the CA behaviour the test changes.
func startCA(t *testing.T, wrap func(*mockserver.MockCA) server.CA) *testCA {
	t.Helper()
	return serveCA(t, wrap, false, nil)
}

// startRewritingCA serves a mock CA over HTTP behind a party on the path that changes every CMP
// response body with the function rewrite builds from the CA certificate.
func startRewritingCA(t *testing.T, rewrite func(caCert *x509.Certificate) func(body []byte) []byte) *testCA {
	t.Helper()
	return serveCA(t, nil, false, rewrite)
}

// startTLSCA serves a mock CA over HTTPS with a certificate that no root trusts.
func startTLSCA(t *testing.T, wrap func(*mockserver.MockCA) server.CA) *testCA {
	t.Helper()
	return serveCA(t, wrap, true, nil)
}

// serveCA serves a mock CA over HTTP, or over HTTPS when overTLS is set. rewrite, when set, builds
// from the CA certificate a function that replaces the body of every CMP response.
func serveCA(t *testing.T, wrap func(*mockserver.MockCA) server.CA, overTLS bool, rewrite func(*x509.Certificate) func([]byte) []byte) *testCA {
	t.Helper()
	mock, err := mockserver.New(map[string][]byte{testRef: []byte(testSecret)}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	var ca server.CA = mock
	if wrap != nil {
		ca = wrap(mock)
	}
	srv := server.NewCAServer(ca,
		server.LightweightPolicy(),
		server.WithSigner(mock.Key(), mock.Cert()),
		server.WithExtraCerts([]*x509.Certificate{mock.Cert()}),
		server.WithSecretLookup(mock),
		server.WithCertificateLookup(mock),
	)
	if err := srv.Err(); err != nil {
		t.Fatal(err)
	}
	tc := &testCA{caFile: filepath.Join(t.TempDir(), "ca.pem")}
	writeFile(t, tc.caFile, pemfile.EncodeCertificates([]*x509.Certificate{mock.Cert()}))
	var rewriteBody func([]byte) []byte
	if rewrite != nil {
		rewriteBody = rewrite(mock.Cert())
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc.requests.Add(1)
		if rewriteBody == nil {
			srv.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		if rec.Header().Get("Content-Type") == "application/pkixcmp" {
			body = rewriteBody(body)
		}
		maps.Copy(w.Header(), rec.Header())
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	}))
	if overTLS {
		// Handshake failures are part of some tests.
		ts.Config.ErrorLog = log.New(io.Discard, "", 0)
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	tc.url = ts.URL + "/cmp"
	return tc
}

// writeFile writes a test fixture.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// useSecret makes the shared secret available through the environment, or removes it when empty.
func useSecret(t *testing.T, value string) {
	t.Helper()
	isolateColorEnv(t)
	t.Setenv(secret.EnvVar, value)
	if value == "" {
		if err := os.Unsetenv(secret.EnvVar); err != nil {
			t.Fatal(err)
		}
	}
}

// readCert parses the single certificate in a PEM file.
func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	certs, err := pemfile.ReadCertificates(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("%s holds %d certificates", path, len(certs))
	}
	return certs[0]
}

// enrollIR runs a MAC-protected IR with a generated key and returns the certificate and key paths.
func enrollIR(t *testing.T, ca *testCA, extra ...string) (certOut, keyOut string) {
	t.Helper()
	dir := t.TempDir()
	certOut, keyOut = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	args := append([]string{
		"enroll", "--server", ca.url, "--ref", testRef,
		"--cert-out", certOut, "--key-out", keyOut,
	}, extra...)
	code, _, errOut := run(t, args...)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	return certOut, keyOut
}

// lookalikeCA returns a self-signed CA certificate with the subject and subject key identifier of
// model but another key, as someone on the path could add to the unprotected extraCerts.
func lookalikeCA(t *testing.T, model *x509.Certificate) *x509.Certificate {
	t.Helper()
	_, cert := testCertificate(t, &x509.Certificate{
		RawSubject:            model.RawSubject,
		SubjectKeyId:          model.SubjectKeyId,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}, nil, nil)
	return cert
}

// insertExtraCert returns the PKIMessage der with cert placed first in extraCerts. The protection
// covers only the header and body, so the message stays valid. PKIMessage is SEQUENCE { header,
// body, protection [0] OPTIONAL, extraCerts [1] OPTIONAL }, and extraCerts is an explicit tag around
// a SEQUENCE OF CMPCertificate.
func insertExtraCert(t *testing.T, der []byte, cert *x509.Certificate) []byte {
	t.Helper()
	var msg asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &msg); err != nil || len(rest) > 0 || msg.Tag != asn1.TagSequence {
		t.Fatalf("not a PKIMessage: %v", err)
	}
	var content, certs []byte
	for elements, i := msg.Bytes, 0; len(elements) > 0; i++ {
		var elem asn1.RawValue
		rest, err := asn1.Unmarshal(elements, &elem)
		if err != nil {
			t.Fatal(err)
		}
		elements = rest
		// The body is a CHOICE whose ip alternative has tag [1] too, so only the elements after
		// the body are matched by tag.
		if i >= 2 && elem.Class == asn1.ClassContextSpecific && elem.Tag == 1 {
			var seq asn1.RawValue
			if _, err := asn1.Unmarshal(elem.Bytes, &seq); err != nil {
				t.Fatal(err)
			}
			certs = seq.Bytes
			continue
		}
		content = append(content, elem.FullBytes...)
	}
	marshal := func(class, tag int, bytes []byte) []byte {
		out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	seq := marshal(asn1.ClassUniversal, asn1.TagSequence, append(append([]byte{}, cert.Raw...), certs...))
	content = append(content, marshal(asn1.ClassContextSpecific, 1, seq)...)
	return marshal(asn1.ClassUniversal, asn1.TagSequence, content)
}

// TestEnrollChainVerifiesSignatures checks that --chain-out holds the CA certificate that signed the
// new certificate and not a certificate that only copies its name and key identifier, with and
// without --ca-cert, and that the profile check reports the look-alike. extraCerts is outside the
// protection of a response, so someone on the path can add certificates to it, and a cr response
// carries no caPubs to prefer.
func TestEnrollChainVerifiesSignatures(t *testing.T) {
	useSecret(t, testSecret)
	ca := startRewritingCA(t, func(caCert *x509.Certificate) func([]byte) []byte {
		lookalike := lookalikeCA(t, caCert)
		return func(body []byte) []byte { return insertExtraCert(t, body, lookalike) }
	})
	caCert := readCert(t, ca.caFile)
	certOut, keyOut := enrollIR(t, ca, "--subject", "CN=device-42")
	for _, pinned := range []bool{true, false} {
		t.Run(fmt.Sprintf("pinned=%t", pinned), func(t *testing.T) {
			dir := t.TempDir()
			chainOut := filepath.Join(dir, "chain.pem")
			args := []string{"enroll", "--server", ca.url, "--type", "cr", "--cert", certOut, "--key", keyOut,
				"--subject", "CN=device-42", "--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"),
				"--chain-out", chainOut}
			if pinned {
				args = append(args, "--ca-cert", ca.caFile)
			}
			code, _, errOut := run(t, args...)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s", code, errOut)
			}
			if !strings.Contains(errOut, "does not start extraCerts with its protection certificate") {
				t.Errorf("the report does not warn about the look-alike protection certificate:\n%s", errOut)
			}
			chain, err := pemfile.ReadCertificates(chainOut)
			if err != nil {
				t.Fatal(err)
			}
			if len(chain) != 1 || !chain[0].Equal(caCert) {
				t.Errorf("chain holds %d certificates, the first signed by %s, want the CA certificate alone", len(chain), chainSigner(chain, caCert))
			}
		})
	}
}

// chainSigner says whether the first certificate of chain is the CA certificate, for a test message.
func chainSigner(chain []*x509.Certificate, caCert *x509.Certificate) string {
	if len(chain) == 0 {
		return "nobody"
	}
	if chain[0].Equal(caCert) {
		return "the CA key"
	}
	return "another key"
}

// TestEnrollIR checks MAC-protected initial enrollment with classical and ML-DSA keys.
func TestEnrollIR(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	for _, keyType := range []string{"ecdsa-p256", "ed25519", "ml-dsa-65"} {
		t.Run(keyType, func(t *testing.T) {
			dir := t.TempDir()
			certOut, keyOut, chainOut := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), filepath.Join(dir, "chain.pem")
			code, out, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef,
				"--subject", "CN=device-42,O=Example", "--san", "device-42.example.com", "--san", "ip:192.0.2.7",
				"--key-type", keyType, "--cert-out", certOut, "--key-out", keyOut, "--chain-out", chainOut)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s", code, errOut)
			}
			cert := readCert(t, certOut)
			if got := cert.Subject.String(); got != "CN=device-42,O=Example" {
				t.Errorf("subject = %q", got)
			}
			if len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 1 {
				t.Errorf("alt names = %v %v", cert.DNSNames, cert.IPAddresses)
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
			if pub, ok := keys.Public(key).(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
				t.Error("the saved key does not match the certificate")
			}
			chain, err := pemfile.ReadCertificates(chainOut)
			if err != nil || len(chain) != 1 || !chain[0].Equal(readCert(t, ca.caFile)) {
				t.Errorf("chain = %d certificates, %v", len(chain), err)
			}
			for _, want := range []string{"ir", "ip  accepted", "certConf", "pkiconf", "PBMAC1"} {
				if !errorContains(errOut, want) {
					t.Errorf("ladder lacks %q:\n%s", want, errOut)
				}
			}
			if !strings.Contains(out, "Certificate issued") || !strings.Contains(out, keyOut) {
				t.Errorf("report:\n%s", out)
			}
		})
	}
}

// TestEnrollDefaults checks that a MAC request without a name asks for the reference as common name
// and that the sender names the reference, as RFC 9483 §4.1.5 describes.
func TestEnrollDefaults(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certOut, _ := enrollIR(t, ca, "--mac", "pbm")
	if got := readCert(t, certOut).Subject.CommonName; got != testRef {
		t.Errorf("subject common name = %q, want %q", got, testRef)
	}
}

// TestEnrollSecretFile checks that the secret is read from a file without its line ending.
func TestEnrollSecretFile(t *testing.T) {
	useSecret(t, "")
	ca := startCA(t, nil)
	file := filepath.Join(t.TempDir(), "secret")
	writeFile(t, file, []byte(testSecret+"\n"))
	enrollIR(t, ca, "--secret-file", file, "--quiet")
}

// TestEnrollSigned checks cr, kur and p10cr requests signed with a certificate from an earlier IR,
// trusting the CA either from its responses or from --ca-cert.
func TestEnrollSigned(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca, "--subject", "CN=device-42")

	csrKey, err := keys.Generate("ecdsa-p384")
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := compositex509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "from-csr"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csrFile := filepath.Join(t.TempDir(), "req.csr")
	writeFile(t, csrFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	tests := []struct {
		name        string
		args        []string
		wantSubject string
	}{
		{"cr", []string{"--type", "cr", "--subject", "CN=second", "--key-out", "KEY"}, "CN=second"},
		{"kur", []string{"--type", "kur", "--key-type", "ml-dsa-44", "--key-out", "KEY"}, "CN=device-42"},
		{"p10cr generated", []string{"--type", "p10cr", "--subject", "CN=p10", "--key-out", "KEY"}, "CN=p10"},
		{"p10cr file", []string{"--type", "p10cr", "--csr", csrFile}, "CN=from-csr"},
		{"kur pinned", []string{"--type", "kur", "--ca-cert", ca.caFile, "--key-out", "KEY"}, "CN=device-42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certOut := filepath.Join(dir, "cert.pem")
			args := []string{"enroll", "--server", ca.url, "--cert", certFile, "--key", keyFile, "--cert-out", certOut}
			for _, a := range tt.args {
				args = append(args, strings.ReplaceAll(a, "KEY", filepath.Join(dir, "key.pem")))
			}
			code, _, errOut := run(t, args...)
			if code != exitOK {
				t.Fatalf("exited with %d:\n%s", code, errOut)
			}
			if got := readCert(t, certOut).Subject.String(); got != tt.wantSubject {
				t.Errorf("subject = %q, want %q", got, tt.wantSubject)
			}
		})
	}
}

// TestEnrollSignedOtherCA checks the hint for a signed response whose signer does not chain to --ca-cert.
func TestEnrollSignedOtherCA(t *testing.T) {
	useSecret(t, testSecret)
	ca, other := startCA(t, nil), startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca)
	dir := t.TempDir()
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--type", "kur", "--cert", certFile, "--key", keyFile,
		"--ca-cert", other.caFile, "--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))
	if code != exitProtocol || !errorContains(errOut, "not signed by the CA in --ca-cert") {
		t.Errorf("exited with %d, want %d with the --ca-cert hint:\n%s", code, exitProtocol, errOut)
	}
}

// TestEnrollMACOtherCA checks that --ca-cert also holds for a MAC-protected enrollment, whose response
// carries the CA certificate of the server in caPubs.
func TestEnrollMACOtherCA(t *testing.T) {
	useSecret(t, testSecret)
	ca, other := startCA(t, nil), startCA(t, nil)
	dir := t.TempDir()
	certOut := filepath.Join(dir, "cert.pem")
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--ca-cert", other.caFile,
		"--cert-out", certOut, "--key-out", filepath.Join(dir, "key.pem"))
	if code != exitProtocol || !errorContains(errOut, "does not chain to the certificates in --ca-cert") {
		t.Errorf("exited with %d, want %d with the --ca-cert hint:\n%s", code, exitProtocol, errOut)
	}
	if _, err := os.Stat(certOut); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s was written for a certificate from another CA", certOut)
	}
}

// TestEnrollComposite checks enrollment of a composite ML-DSA key and that the certificate signs a key
// update and a revocation.
func TestEnrollComposite(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	alg := compositemldsa.Algorithms()[0]
	name := strings.ToLower(alg.String())
	certOut, keyOut := enrollIR(t, ca, "--key-type", name)
	pub, err := keys.CertificateKey(readCert(t, certOut))
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.Describe(pub); got != alg.String() {
		t.Errorf("key = %q, want %q", got, alg.String())
	}

	dir := t.TempDir()
	newCert, newKey := filepath.Join(dir, "new.pem"), filepath.Join(dir, "new.key")
	steps := [][]string{
		{"enroll", "--server", ca.url, "--type", typeKUR, "--cert", certOut, "--key", keyOut,
			"--key-type", name, "--cert-out", newCert, "--key-out", newKey},
		{"revoke", "--server", ca.url, "--cert", newCert, "--key", newKey, "--yes"},
	}
	for _, args := range steps {
		if code, _, errOut := run(t, args...); code != exitOK {
			t.Fatalf("%s exited with %d:\n%s", args[0], code, errOut)
		}
	}
}

// unconfirmingCA refuses every certificate confirmation.
type unconfirmingCA struct {
	*mockserver.MockCA
}

// ConfirmCertificate fails, which makes the server reject the certConf.
func (unconfirmingCA) ConfirmCertificate(context.Context, *x509.Certificate, server.ConfirmStatus, any) error {
	return errors.New("confirmation refused")
}

// TestEnrollFailures checks the exit status and explanation of each failure class.
func TestEnrollFailures(t *testing.T) {
	ca := startCA(t, nil)
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html>login</html>")
	}))
	t.Cleanup(html.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	unconfirming := startCA(t, func(m *mockserver.MockCA) server.CA { return unconfirmingCA{m} })
	other := startCA(t, nil)

	tests := []struct {
		name     string
		secret   string
		server   string
		extra    []string
		wantCode int
		want     string
	}{
		{"wrong secret", "wrong", ca.url, nil, exitRejected, "badMessageCheck"},
		{"wrong secret pinned", "wrong", ca.url, []string{"--ca-cert", ca.caFile}, exitRejected, "badMessageCheck"},
		{"wrong secret other CA", "wrong", ca.url, []string{"--ca-cert", other.caFile}, exitRejected, "not authenticated"},
		{"not found", testSecret, notFound.URL, nil, exitTransport, "HTTP 404"},
		{"not CMP", testSecret, html.URL, nil, exitTransport, "text/html"},
		{"connection refused", testSecret, closed.URL, nil, exitTransport, "Check the host and port"},
		{"unconfirmed", testSecret, unconfirming.url, nil, exitUnconfirmed, "confirmation failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useSecret(t, tt.secret)
			dir := t.TempDir()
			certOut := filepath.Join(dir, "cert.pem")
			args := append([]string{"enroll", "--server", tt.server, "--ref", testRef,
				"--cert-out", certOut, "--key-out", filepath.Join(dir, "key.pem")}, tt.extra...)
			code, _, errOut := run(t, args...)
			if code != tt.wantCode || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.wantCode, tt.want, errOut)
			}
			_, statErr := os.Stat(certOut)
			if saved := statErr == nil; saved != (tt.wantCode == exitUnconfirmed) {
				t.Errorf("certificate saved = %v", saved)
			}
		})
	}
}

// TestEnrollUsage checks that invalid command lines fail with status 1 before anything is sent.
func TestEnrollUsage(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	existing := filepath.Join(t.TempDir(), "existing.pem")
	writeFile(t, existing, []byte("keep"))
	dir := t.TempDir()
	out, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no protection", []string{"--cert-out", out, "--key-out", key}, "choose a protection"},
		{"both protections", []string{"--ref", testRef, "--cert", existing, "--key", existing, "--cert-out", out}, "choose one protection"},
		{"kur without cert", []string{"--type", "kur", "--ref", testRef, "--cert-out", out, "--key-out", key}, "kur"},
		{"no key output", []string{"--ref", testRef, "--cert-out", out}, "--key-out"},
		{"existing output", []string{"--ref", testRef, "--cert-out", existing, "--key-out", key}, "already exists"},
		{"same output twice", []string{"--ref", testRef, "--cert-out", out, "--key-out", out}, "two outputs"},
		{"bad subject", []string{"--ref", testRef, "--subject", "XX=1", "--cert-out", out, "--key-out", key}, "unknown attribute type"},
		{"bad key type", []string{"--ref", testRef, "--key-type", "dsa", "--cert-out", out, "--key-out", key}, "unknown key type"},
		{"csr outside p10cr", []string{"--ref", testRef, "--csr", existing, "--cert-out", out}, "--type p10cr"},
		{"bad type", []string{"--type", "xx", "--ref", testRef, "--cert-out", out, "--key-out", key}, "invalid --type"},
		{"missing server", []string{"--server", "", "--ref", testRef, "--cert-out", out, "--key-out", key}, "--server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"enroll", "--server", ca.url}, tt.args...)
			code, _, errOut := run(t, args...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want 1 and %q in:\n%s", code, tt.want, errOut)
			}
		})
	}
	if n := ca.requests.Load(); n != 0 {
		t.Errorf("the CA received %d requests", n)
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep" {
		t.Error("an existing file was overwritten")
	}
}

// TestEnrollMissingSecret checks the error when no secret source is available.
func TestEnrollMissingSecret(t *testing.T) {
	useSecret(t, "")
	ca := startCA(t, nil)
	dir := t.TempDir()
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef,
		"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"))
	if code != exitLocal || !errorContains(errOut, secret.EnvVar) {
		t.Errorf("exited with %d:\n%s", code, errOut)
	}
}

// TestEnrollForce checks that --force replaces existing outputs.
func TestEnrollForce(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certOut, keyOut := enrollIR(t, ca)
	first := readCert(t, certOut)
	code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut, "--force", "-q")
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	if readCert(t, certOut).Equal(first) {
		t.Error("the certificate was not replaced")
	}
}

// TestEnrollHints checks the hints for a CA that rejects PBMAC1 and for a new certificate whose issuer
// is missing.
func TestEnrollHints(t *testing.T) {
	useSecret(t, testSecret)
	dir := t.TempDir()
	enroll := func(url string, extra ...string) (int, string) {
		t.Helper()
		args := append([]string{"enroll", "--server", url, "--ref", testRef, "--force",
			"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem")}, extra...)
		code, _, errOut := run(t, args...)
		return code, errOut
	}

	const pbm = "Try --mac pbm."
	rejection := func(info pkicmp.PKIFailureInfo, text ...string) pkicmp.PKIStatusInfo {
		return pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, FailInfo: info, StatusString: text}
	}
	rejections := []struct {
		name    string
		status  pkicmp.PKIStatusInfo
		mac     string
		want    string
		wantPBM bool
	}{
		{"no signer for PBMAC1", rejection(pkicmp.FailBadRequest, "no suitable sender cert"), "pbmac1", "does not accept", true},
		{"no signer for PBM", rejection(pkicmp.FailBadRequest, "no suitable sender cert"), "pbm", "does not accept", false},
		{"other bad request", rejection(pkicmp.FailBadRequest, "Illegal key algorithm"), "pbmac1", "does not accept", false},
		{"bad message check", rejection(pkicmp.FailBadMessageCheck), "pbmac1", "Check the shared secret", true},
		{"wrong integrity", rejection(pkicmp.FailWrongIntegrity), "pbmac1", "other kind of protection", true},
	}
	for _, tt := range rejections {
		code, errOut := enroll(rejectingServer(t, tt.status), "--mac", tt.mac)
		if code != exitRejected || !errorContains(errOut, tt.want) || errorContains(errOut, pbm) != tt.wantPBM {
			t.Errorf("%s: exited with %d, want %d with %q and the --mac pbm hint %v:\n%s",
				tt.name, code, exitRejected, tt.want, tt.wantPBM, errOut)
		}
	}

	// The CA issues from an intermediate CA that no response carries.
	var issuing intermediateCA
	ca := startCA(t, func(m *mockserver.MockCA) server.CA {
		issuing = newIntermediateCA(t, m)
		return issuing
	})
	proxy := stripExtraCerts(t, ca.url)
	tests := []struct {
		name  string
		extra []string
		hint  string
	}{
		{"first response", nil, "Pass it with --ca-cert."},
		{"pinned", []string{"--ca-cert", ca.caFile}, "Add the CA certificate that issued it."},
	}
	for _, tt := range tests {
		code, errOut := enroll(proxy, tt.extra...)
		if code != exitProtocol || !errorContains(errOut, tt.hint) || !errorContains(errOut, "trusted certificate: x509:") {
			t.Errorf("%s: exited with %d, want %d with %q:\n%s", tt.name, code, exitProtocol, tt.hint, errOut)
		}
	}
}
