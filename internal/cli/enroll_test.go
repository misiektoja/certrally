package cli

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc.requests.Add(1)
		srv.ServeHTTP(w, r)
	}))
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
			if pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
				t.Error("the saved key does not match the certificate")
			}
			chain, err := pemfile.ReadCertificates(chainOut)
			if err != nil || len(chain) != 1 || !chain[0].Equal(readCert(t, ca.caFile)) {
				t.Errorf("chain = %d certificates, %v", len(chain), err)
			}
			for _, want := range []string{"ir", "ip  accepted", "certConf", "pkiconf", "PBMAC1"} {
				if !strings.Contains(errOut, want) {
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

// compositeCA issues certificates with compositex509, which composite ML-DSA keys require.
type compositeCA struct {
	*mockserver.MockCA
}

// IssueCertificate signs the template like the mock CA, through compositex509.
func (c compositeCA) IssueCertificate(_ context.Context, reqType server.RequestType, tmpl *x509.Certificate, _ *server.SenderIdentity) (*server.Response, error) {
	serial, err := server.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := compositex509.CreateCertificate(rand.Reader, tmpl, c.Cert(), tmpl.PublicKey, c.Key())
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	resp := &server.Response{Certificate: cert}
	if reqType == server.RequestIR {
		resp.CACerts = []*x509.Certificate{c.Cert()}
	}
	return resp, nil
}

// TestEnrollComposite checks enrollment of a composite ML-DSA key.
func TestEnrollComposite(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, func(m *mockserver.MockCA) server.CA { return compositeCA{m} })
	alg := compositemldsa.Algorithms()[0]
	name := strings.ToLower(alg.String())
	certOut, _ := enrollIR(t, ca, "--key-type", name)
	pub, err := keys.CertificateKey(readCert(t, certOut))
	if err != nil {
		t.Fatal(err)
	}
	if got := keys.Describe(pub); got != alg.String() {
		t.Errorf("key = %q, want %q", got, alg.String())
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
			if code != tt.wantCode || !strings.Contains(errOut, tt.want) {
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
			if code != exitLocal || !strings.Contains(errOut, tt.want) {
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
	if code != exitLocal || !strings.Contains(errOut, secret.EnvVar) {
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
