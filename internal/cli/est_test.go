package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/cmpfile"
	"github.com/misiektoja/certrally/internal/estca"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
)

// The credentials the EST test servers accept.
const (
	estTestUser     = "device"
	estTestPassword = "s3cret-pass"
)

// estTestServer is an EST server that runs for one test.
type estTestServer struct {
	url    string
	caFile string
	ca     *estca.CA
}

// usePassword makes the EST password available through the environment, or removes it when empty.
func usePassword(t *testing.T, value string) {
	t.Helper()
	isolateColorEnv(t)
	t.Setenv(secret.PasswordEnvVar, value)
	if value == "" {
		if err := os.Unsetenv(secret.PasswordEnvVar); err != nil {
			t.Fatal(err)
		}
	}
}

// startESTServer serves h over TLS with a server certificate of ca. A nil h serves the router of est
// mock for estTestUser. configure, if set, changes the TLS configuration before the server starts.
func startESTServer(t *testing.T, ca *estca.CA, h http.Handler, configure func(*tls.Config)) *estTestServer {
	t.Helper()
	if ca == nil {
		var err error
		if ca, err = estca.New(); err != nil {
			t.Fatal(err)
		}
	}
	if h == nil {
		router, err := newESTMockRouter(ca, estTestUser, []byte(estTestPassword), nil)
		if err != nil {
			t.Fatal(err)
		}
		h = router
	}
	serverCert, err := ca.ServerCertificate([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	if configure != nil {
		configure(ts.TLS)
	}
	// Handshake failures are part of some tests.
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	srv := &estTestServer{url: ts.URL, caFile: filepath.Join(t.TempDir(), "ca.pem"), ca: ca}
	writeFile(t, srv.caFile, pemfile.EncodeCertificates([]*x509.Certificate{ca.Certificate()}))
	return srv
}

// args returns the flags that reach and trust the server, followed by extra.
func (s *estTestServer) args(command string, extra ...string) []string {
	return append([]string{"est", command, "--server", s.url, "--tls-ca-cert", s.caFile}, extra...)
}

// estRequestOperations lists the operation of every request in the exchange.
func estRequestOperations(doc map[string]any) string {
	events, _ := doc["exchange"].([]any)
	var ops []string
	for _, ev := range events {
		if get(ev, "kind") == "request" {
			op, _ := get(ev, "operation").(string)
			ops = append(ops, op)
		}
	}
	return strings.Join(ops, " ")
}

// text returns v if it is a string and "" otherwise.
func text(v any) string {
	s, _ := v.(string)
	return s
}

// hasWarning reports whether a warning of the document contains text.
func hasWarning(doc map[string]any, text string) bool {
	warnings, _ := doc["warnings"].([]any)
	for _, w := range warnings {
		if s, _ := w.(string); strings.Contains(s, text) {
			return true
		}
	}
	return false
}

// TestESTEnrollAndRenew checks enrollment, both kinds of renewal and server key generation against
// the test CA.
func TestESTEnrollAndRenew(t *testing.T) {
	usePassword(t, estTestPassword)
	srv := startESTServer(t, nil, nil, nil)
	dir := t.TempDir()

	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, doc := runJSON(t, srv.args("enroll", "--user", estTestUser, "--subject", "CN=dev-1,O=Example",
		"--san", "dns:dev-1.example.com", "--cert-out", certOut, "--key-out", keyOut)...)
	if code != exitOK {
		t.Fatalf("est enroll exited with %d: %v", code, doc["error"])
	}
	cert := readCert(t, certOut)
	if cert.Subject.CommonName != "dev-1" || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "dev-1.example.com" {
		t.Errorf("certificate subject %s, DNS names %v", cert.Subject, cert.DNSNames)
	}
	if got := estRequestOperations(doc); got != "simpleenroll" {
		t.Errorf("requests %q, want simpleenroll", got)
	}
	if get(doc, "exchange.0.kind") != "connect" || get(doc, "exchange.0.tls.server") == nil {
		t.Errorf("first record %v, want the connection with the server certificate", get(doc, "exchange.0"))
	}
	if get(doc, "result.key") != "ECDSA P-256" || get(doc, "result.certificate.subject") != "CN=dev-1,O=Example" {
		t.Errorf("result %v", doc["result"])
	}

	t.Run("client certificate", func(t *testing.T) {
		newCert, newKey := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
		code, doc := runJSON(t, srv.args("reenroll", "--cert", certOut, "--key", keyOut, "--cert-out", newCert, "--key-out", newKey)...)
		if code != exitOK {
			t.Fatalf("est reenroll exited with %d: %v", code, doc["error"])
		}
		renewed := readCert(t, newCert)
		if !bytes.Equal(renewed.RawSubject, cert.RawSubject) || len(renewed.DNSNames) != 1 {
			t.Errorf("renewed certificate %s with %v does not repeat the subject and SAN", renewed.Subject, renewed.DNSNames)
		}
		if bytes.Equal(renewed.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
			t.Error("renewal kept the key without --new-key")
		}
		if got := estRequestOperations(doc); got != "simplereenroll" {
			t.Errorf("requests %q, want simplereenroll", got)
		}
	})

	t.Run("password and same key", func(t *testing.T) {
		newCert := filepath.Join(t.TempDir(), "cert.pem")
		code, doc := runJSON(t, srv.args("reenroll", "--cert", certOut, "--user", estTestUser, "--new-key", keyOut, "--cert-out", newCert)...)
		if code != exitOK {
			t.Fatalf("est reenroll exited with %d: %v", code, doc["error"])
		}
		if renewed := readCert(t, newCert); !bytes.Equal(renewed.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
			t.Error("renewal with --new-key certified another key")
		}
		if doc["result"].(map[string]any)["key"] != nil {
			t.Errorf("result names a key for --new-key: %v", doc["result"])
		}
	})

	t.Run("serverkeygen", func(t *testing.T) {
		skgCert, skgKey := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
		code, doc := runJSON(t, srv.args("serverkeygen", "--user", estTestUser, "--subject", "CN=skg", "--key-type", "ml-dsa-44",
			"--cert-out", skgCert, "--key-out", skgKey)...)
		if code != exitOK {
			t.Fatalf("est serverkeygen exited with %d: %v", code, doc["error"])
		}
		data, err := os.ReadFile(skgKey)
		if err != nil {
			t.Fatal(err)
		}
		key, err := keys.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := keys.CertificateKey(readCert(t, skgCert))
		if err != nil {
			t.Fatal(err)
		}
		if !keys.Public(key).(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
			t.Error("the saved key does not belong to the certificate")
		}
		info, err := os.Stat(skgKey)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %v, want 0600", info.Mode())
		}
		if desc, _ := get(doc, "result.key").(string); !strings.Contains(desc, "ML-DSA-44") {
			t.Errorf("result key %q, want ML-DSA-44", desc)
		}
	})
}

// TestESTCACertsAndCSRAttrs checks the reports of est cacerts and est csrattrs.
func TestESTCACertsAndCSRAttrs(t *testing.T) {
	usePassword(t, "")
	srv := startESTServer(t, nil, nil, nil)
	out := filepath.Join(t.TempDir(), "cacerts.pem")
	code, doc := runJSON(t, srv.args("cacerts", "--out", out)...)
	if code != exitOK {
		t.Fatalf("est cacerts exited with %d: %v", code, doc["error"])
	}
	if get(doc, "result.verified") != "tls" || get(doc, "result.tlsIssued") != true {
		t.Errorf("result %v", doc["result"])
	}
	if saved := readCert(t, out); !saved.Equal(srv.ca.Certificate()) {
		t.Error("the saved certificate is not the CA certificate")
	}

	code, doc = runJSON(t, srv.args("csrattrs")...)
	if code != exitOK {
		t.Fatalf("est csrattrs exited with %d: %v", code, doc["error"])
	}
	attrs, _ := get(doc, "result.attributes").([]any)
	names := make([]string, 0, len(attrs))
	for _, a := range attrs {
		names = append(names, get(a, "name").(string))
	}
	if strings.Join(names, " ") != "challengePassword ECDSA SHA-256 ecPublicKey" {
		t.Errorf("attributes %v", names)
	}
	if got := get(doc, "result.attributes.2.values.0"); got != "1.2.840.10045.3.1.7" {
		t.Errorf("ecPublicKey value %v, want the P-256 OID", got)
	}
}

// TestESTBootstrap checks est cacerts --bootstrap with and without a fingerprint.
func TestESTBootstrap(t *testing.T) {
	usePassword(t, "")
	srv := startESTServer(t, nil, nil, nil)
	sum := sha256.Sum256(srv.ca.Certificate().Raw)
	fingerprint := hex.EncodeToString(sum[:])
	base := []string{"est", "cacerts", "--server", srv.url, "--bootstrap"}
	dir := t.TempDir()

	out := filepath.Join(dir, "ok.pem")
	code, doc := runJSON(t, append(base, "--fingerprint", strings.ToUpper(fingerprint), "--out", out)...)
	if code != exitOK || get(doc, "result.verified") != "fingerprint" {
		t.Fatalf("exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	readCert(t, out)

	wrong := strings.Repeat("ab", sha256.Size)
	out = filepath.Join(dir, "wrong.pem")
	code, doc = runJSON(t, append(base, "--fingerprint", wrong, "--out", out)...)
	if code != exitProtocol || get(doc, "error.title") != "No CA certificate has the expected fingerprint" {
		t.Errorf("wrong fingerprint: exit %d, error %v", code, doc["error"])
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("certificates with the wrong fingerprint were saved")
	}

	code, _, errOut := run(t, append(base, "--out", filepath.Join(dir, "unchecked.pem"))...)
	if code != exitLocal || !errorContains(errOut, "--fingerprint") {
		t.Errorf("bootstrap without a check: exit %d:\n%s", code, errOut)
	}

	code, doc = runJSON(t, base...)
	if code != exitOK || get(doc, "result.verified") != "none" || len(get(doc, "result.saved").([]any)) != 0 {
		t.Errorf("bootstrap without --out: exit %d, result %v", code, doc["result"])
	}

	code, _, errOut = run(t, append(base, "--fingerprint", "12:34")...)
	if code != exitLocal || !errorContains(errOut, "64 hex digits") {
		t.Errorf("short fingerprint: exit %d:\n%s", code, errOut)
	}
}

// bundleHandler answers every request with certs as a certs-only PKCS#7, the form of a cacerts
// response.
func bundleHandler(t *testing.T, certs []*x509.Certificate) http.Handler {
	t.Helper()
	var der []byte
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	p7, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(p7))
	})
}

// testCAPair returns a self-signed root CA certificate and the certificate of a CA it issued.
func testCAPair(t *testing.T) (root, sub *x509.Certificate) {
	t.Helper()
	template := func(name string) *x509.Certificate {
		return &x509.Certificate{
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	rootKey, root := testCertificate(t, template("Test Root CA"), nil, nil)
	_, sub = testCertificate(t, template("Test Issuing CA"), root, rootKey)
	return root, sub
}

// fingerprintOf returns the hex SHA-256 fingerprint of cert.
func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// TestESTBootstrapSavesCheckedCertificates checks that est cacerts --bootstrap --fingerprint saves
// the certificate with that fingerprint and the certificates it issued, and reports the rest of the
// response as unverified without saving it.
func TestESTBootstrapSavesCheckedCertificates(t *testing.T) {
	usePassword(t, "")
	ca, err := estca.New()
	if err != nil {
		t.Fatal(err)
	}
	other, err := estca.New()
	if err != nil {
		t.Fatal(err)
	}
	root, sub := testCAPair(t)
	tests := []struct {
		name        string
		bundle      []*x509.Certificate
		fingerprint *x509.Certificate
		want        []*x509.Certificate
		unverified  int
		tlsIssued   bool
	}{
		{"the matched certificate", []*x509.Certificate{other.Certificate(), ca.Certificate()}, ca.Certificate(), []*x509.Certificate{ca.Certificate()}, 1, true},
		{"another matched certificate", []*x509.Certificate{other.Certificate(), ca.Certificate()}, other.Certificate(), []*x509.Certificate{other.Certificate()}, 1, false},
		{"the certificates it issued", []*x509.Certificate{sub, other.Certificate(), root}, root, []*x509.Certificate{sub, root}, 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startESTServer(t, ca, bundleHandler(t, tc.bundle), nil)
			out := filepath.Join(t.TempDir(), "ca.pem")
			code, doc := runJSON(t, "est", "cacerts", "--server", srv.url, "--bootstrap", "--fingerprint", fingerprintOf(tc.fingerprint), "--out", out)
			if code != exitOK || get(doc, "result.verified") != "fingerprint" {
				t.Fatalf("exit %d, result %v, error %v", code, doc["result"], doc["error"])
			}
			saved, err := pemfile.ReadCertificates(out)
			if err != nil {
				t.Fatal(err)
			}
			if len(saved) != len(tc.want) {
				t.Fatalf("saved %d certificates, want %d", len(saved), len(tc.want))
			}
			for i := range saved {
				if !saved[i].Equal(tc.want[i]) {
					t.Errorf("saved certificate %d is %s, want %s", i, saved[i].Subject, tc.want[i].Subject)
				}
			}
			if received, _ := get(doc, "result.certificates").([]any); len(received) != len(tc.bundle) {
				t.Errorf("the result lists %d certificates, want all %d received", len(received), len(tc.bundle))
			}
			if unverified, _ := get(doc, "result.unverified").([]any); len(unverified) != tc.unverified {
				t.Errorf("unverified = %v, want %d certificates", unverified, tc.unverified)
			}
			if tc.unverified > 0 && !hasWarning(doc, "was not saved") {
				t.Errorf("no warning about the unsaved certificate: %v", doc["warnings"])
			}
			if got := get(doc, "result.tlsIssued"); got != tc.tlsIssued {
				t.Errorf("tlsIssued = %v, want %v", got, tc.tlsIssued)
			}
		})
	}
}

// TestESTBootstrapConfirm checks the questions est cacerts --bootstrap asks on a terminal: which
// certificate has the published fingerprint, or whether the only one does.
func TestESTBootstrapConfirm(t *testing.T) {
	usePassword(t, "")
	ca, err := estca.New()
	if err != nil {
		t.Fatal(err)
	}
	other, err := estca.New()
	if err != nil {
		t.Fatal(err)
	}
	const which = "Which certificate has the SHA-256 fingerprint the CA published?"
	const single = "Does the SHA-256 fingerprint match the one the CA published?"
	bundle := []*x509.Certificate{other.Certificate(), ca.Certificate()}
	tests := []struct {
		name   string
		bundle []*x509.Certificate
		answer map[string]string
		want   []*x509.Certificate
		errMsg string
	}{
		{"chosen certificate", bundle, map[string]string{which: "1"}, []*x509.Certificate{ca.Certificate()}, ""},
		{"none of them", bundle, map[string]string{which: ""}, nil, "no fingerprint was confirmed"},
		{"cancelled", bundle, map[string]string{which: stop}, nil, "no fingerprint was confirmed"},
		{"single certificate confirmed", bundle[1:], map[string]string{single: "yes"}, []*x509.Certificate{ca.Certificate()}, ""},
		{"single certificate denied", bundle[1:], map[string]string{single: "no"}, nil, "no fingerprint was confirmed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := startESTServer(t, ca, bundleHandler(t, tc.bundle), nil)
			useWizard(t, tc.answer)
			out := filepath.Join(t.TempDir(), "ca.pem")
			code, outText, errOut := run(t, "est", "cacerts", "--server", srv.url, "--bootstrap", "--out", out)
			if tc.errMsg != "" {
				if code == exitOK || !errorContains(errOut, tc.errMsg) {
					t.Fatalf("exit %d:\n%s", code, errOut)
				}
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Error("certificates were saved without a confirmed fingerprint")
				}
				return
			}
			if code != exitOK {
				t.Fatalf("exit %d:\n%s", code, errOut)
			}
			saved, err := pemfile.ReadCertificates(out)
			if err != nil {
				t.Fatal(err)
			}
			if len(saved) != len(tc.want) || !saved[0].Equal(tc.want[0]) {
				t.Errorf("saved %d certificates, the first %s", len(saved), saved[0].Subject)
			}
			if !strings.Contains(outText, "was confirmed") {
				t.Errorf("report:\n%s", outText)
			}
		})
	}
}

// pendingServer starts the test CA, which answers the first request for each key with 202 and
// Retry-After seconds.
func pendingServer(t *testing.T, seconds int) *estTestServer {
	t.Helper()
	ca, err := estca.New()
	if err != nil {
		t.Fatal(err)
	}
	ca.RetryAfter = seconds
	return startESTServer(t, ca, nil, nil)
}

// TestESTRetryAfter checks that enrollment waits as a 202 response asks, within --timeout.
func TestESTRetryAfter(t *testing.T) {
	usePassword(t, estTestPassword)
	srv := pendingServer(t, 1)
	dir := t.TempDir()
	code, doc := runJSON(t, srv.args("enroll", "--user", estTestUser, "--subject", "CN=waiting",
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))...)
	if code != exitOK {
		t.Fatalf("est enroll exited with %d: %v", code, doc["error"])
	}
	if got := estRequestOperations(doc); got != "simpleenroll simpleenroll" {
		t.Errorf("requests %q, want the request and its retry", got)
	}
	if get(doc, "exchange.2.httpStatus") != float64(http.StatusAccepted) || get(doc, "exchange.2.retryAfter") != float64(1) {
		t.Errorf("first response %v, want 202 with Retry-After 1", get(doc, "exchange.2"))
	}

	code, doc = runJSON(t, pendingServer(t, 600).args("enroll", "--user", estTestUser, "--subject", "CN=late", "--timeout", "2s",
		"--cert-out", filepath.Join(dir, "late.pem"), "--key-out", filepath.Join(dir, "late.key"))...)
	if code != exitTransport || !strings.Contains(text(get(doc, "error.hint")), "Raise --timeout above 10m0s") {
		t.Errorf("long wait: exit %d, error %v", code, doc["error"])
	}
}

// estErrorHandler answers every request with status, a text body and an optional Retry-After.
func estErrorHandler(status int, contentType, body, retryAfter string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

// TestESTRefusals checks the exit status and report of HTTP errors from the server.
func TestESTRefusals(t *testing.T) {
	srv := startESTServer(t, nil, nil, nil)
	enroll := func(t *testing.T, srv *estTestServer, extra ...string) (int, map[string]any) {
		t.Helper()
		dir := t.TempDir()
		args := srv.args("enroll", append(extra, "--subject", "CN=refused",
			"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))...)
		return runJSON(t, args...)
	}

	t.Run("wrong password", func(t *testing.T) {
		usePassword(t, "wrong")
		code, doc := enroll(t, srv, "--user", estTestUser)
		if code != exitRejected || get(doc, "error.httpStatus") != float64(http.StatusUnauthorized) ||
			get(doc, "error.hint") != "Check --user and the password." {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		usePassword(t, "")
		code, doc := enroll(t, srv)
		if code != exitRejected || !strings.HasPrefix(text(get(doc, "error.hint")), "Sign in with --user") {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		usePassword(t, estTestPassword)
		busy := startESTServer(t, nil, estErrorHandler(http.StatusServiceUnavailable, "text/plain", "down for maintenance", "30"), nil)
		code, doc := enroll(t, busy, "--user", estTestUser)
		if code != exitRejected || get(doc, "error.retryAfter") != float64(30) || get(doc, "error.statusText.0") != "down for maintenance" {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})
}

// TestESTTransportProblems checks answers that are not EST and failed TLS handshakes.
func TestESTTransportProblems(t *testing.T) {
	usePassword(t, "")
	tests := []struct {
		name      string
		handler   http.Handler
		configure func(*tls.Config)
		trusted   bool
		want      string
	}{
		{name: "untrusted server", want: "est cacerts --bootstrap"},
		{
			name:    "wrong path",
			handler: estErrorHandler(http.StatusNotFound, "text/html", "<html>not found</html>", ""),
			trusted: true,
			want:    "Check the path and CA label in --server.",
		},
		{
			name:    "web page",
			handler: estErrorHandler(http.StatusOK, "text/html", "<html>hello</html>", ""),
			trusted: true,
			want:    "instead of an EST response",
		},
		{
			name:      "client certificate required",
			configure: func(c *tls.Config) { c.ClientAuth = tls.RequireAnyClientCert },
			trusted:   true,
			want:      "The server asks for a TLS client certificate. Sign in with --cert and --key.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startESTServer(t, nil, tt.handler, tt.configure)
			args := []string{"est", "cacerts", "--server", srv.url}
			if tt.trusted {
				args = append(args, "--tls-ca-cert", srv.caFile)
			}
			code, doc := runJSON(t, args...)
			report := text(get(doc, "error.message")) + "\n" + text(get(doc, "error.hint"))
			if code != exitTransport || !strings.Contains(report, tt.want) {
				t.Errorf("exit %d, error %v, want %q", code, doc["error"], tt.want)
			}
		})
	}
}

// chainHandler issues certificates with ca and answers with the CA certificate added, which RFC
// 7030 section 4.2.3 does not allow.
func chainHandler(t *testing.T, ca *estca.CA) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		der, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			t.Error(err)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Error(err)
			return
		}
		cert, err := ca.Enroll(r.Context(), csr, "", r)
		if err != nil {
			t.Error(err)
			return
		}
		p7, err := pkcs7.DegenerateCertificate(append(cert.Raw, ca.Certificate().Raw...))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(p7))
	})
}

// TestESTProfile checks how the profiles treat responses that break RFC 7030, and that lint finds
// the same deviation in the capture.
func TestESTProfile(t *testing.T) {
	usePassword(t, estTestPassword)
	ca, err := estca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := startESTServer(t, ca, chainHandler(t, ca), nil)
	dir := t.TempDir()
	capture := filepath.Join(dir, "run.jsonl")
	enroll := func(name string, extra ...string) (int, map[string]any) {
		return runJSON(t, srv.args("enroll", append(extra, "--user", estTestUser, "--subject", "CN="+name,
			"--cert-out", filepath.Join(dir, name+".pem"), "--key-out", filepath.Join(dir, name+".key"))...)...)
	}

	code, doc := enroll("compatible", "--capture", capture)
	if code != exitOK || !hasWarning(doc, "carries 2 certificates instead of only the issued one") {
		t.Errorf("compatible: exit %d, warnings %v, error %v", code, doc["warnings"], doc["error"])
	}
	if cert := readCert(t, filepath.Join(dir, "compatible.pem")); cert.Subject.CommonName != "compatible" {
		t.Errorf("saved %s instead of the issued certificate", cert.Subject)
	}

	code, doc = enroll("strict", "--profile", "strict")
	if code != exitProfile || get(doc, "error.title") != "The response breaks the strict profile" {
		t.Errorf("strict: exit %d, error %v", code, doc["error"])
	}
	if _, err := os.Stat(filepath.Join(dir, "strict.pem")); !os.IsNotExist(err) {
		t.Error("strict saved the certificate")
	}

	code, doc = runJSON(t, "lint", capture)
	if code != exitProfile || get(doc, "result.checked") != float64(1) || get(doc, "result.findings.0.rule") != "RFC 7030 section 4.2.3" ||
		get(doc, "result.findings.0.body") != "simpleenroll" {
		t.Errorf("lint: exit %d, result %v", code, doc["result"])
	}

	code, doc = runJSON(t, "inspect", capture)
	if code != exitOK || get(doc, "result.messages.1.protocol") != protocolEST || get(doc, "result.messages.1.est.content") != "certs-only" ||
		len(get(doc, "result.messages.1.certificates").([]any)) != 2 || get(doc, "result.messages.0.requests.0.subject") != "CN=compatible" {
		t.Errorf("inspect: exit %d, result %v", code, doc["result"])
	}
}

// TestESTAcceptedWithoutRetryAfter checks a 202 response without Retry-After, which RFC 7030
// section 4.2.3 does not allow.
func TestESTAcceptedWithoutRetryAfter(t *testing.T) {
	usePassword(t, estTestPassword)
	srv := startESTServer(t, nil, estErrorHandler(http.StatusAccepted, "", "", ""), nil)
	dir := t.TempDir()
	args := srv.args("enroll", "--user", estTestUser, "--subject", "CN=pending", "--timeout", "3s",
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))

	code, doc := runJSON(t, append(args, "--profile", "strict")...)
	if code != exitProfile {
		t.Errorf("strict: exit %d, error %v", code, doc["error"])
	}
	// The default wait of 10 seconds does not fit in --timeout.
	code, doc = runJSON(t, args...)
	if code != exitTransport || !hasWarning(doc, "has status 202 but no Retry-After header") {
		t.Errorf("compatible: exit %d, warnings %v, error %v", code, doc["warnings"], doc["error"])
	}
}

// TestESTTLSUnique checks that --tls-unique adds the tls-unique value over TLS 1.2 and warns over
// TLS 1.3.
func TestESTTLSUnique(t *testing.T) {
	usePassword(t, estTestPassword)
	tls12 := startESTServer(t, nil, nil, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })
	tls13 := startESTServer(t, nil, nil, nil)
	oidChallengePassword, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		srv  *estTestServer
		want bool
	}{{"TLS 1.2", tls12, true}, {"TLS 1.3", tls13, false}} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			capture := filepath.Join(dir, "run.jsonl")
			code, doc := runJSON(t, tt.srv.args("enroll", "--user", estTestUser, "--subject", "CN=bound", "--tls-unique",
				"--capture", capture, "--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))...)
			if code != exitOK {
				t.Fatalf("exit %d, error %v", code, doc["error"])
			}
			if warned := hasWarning(doc, "has no tls-unique value"); warned == tt.want {
				t.Errorf("warnings %v", doc["warnings"])
			}
			msgs, err := cmpfile.Read(capture, nil)
			if err != nil {
				t.Fatal(err)
			}
			if bound := bytes.Contains(msgs[0].DER, oidChallengePassword); bound != tt.want {
				t.Errorf("request carries a challenge password: %v, want %v", bound, tt.want)
			}
		})
	}
}

// estMockRun is an est mock that runs while a test talks to it.
type estMockRun struct {
	*mockRun
	srpURL string
}

// Addresses in the startup report of est mock.
var (
	estMockServerURL = regexp.MustCompile(`Server\s+(https://\S+)`)
	estMockSRPURL    = regexp.MustCompile(`TLS-SRP\s+(https://\S+)`)
)

// startESTMock runs est mock with args until the test ends or stop is called.
func startESTMock(t *testing.T, args ...string) *estMockRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &estMockRun{mockRun: &mockRun{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}}
	go func() { m.done <- Run(ctx, append([]string{"est", "mock"}, args...), m.stdout, m.stderr) }()
	t.Cleanup(func() {
		cancel()
		<-m.done
	})
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(m.stdout.String(), "Press Ctrl-C to stop.") {
		select {
		case code := <-m.done:
			m.done <- code
			t.Fatalf("est mock exited with %d before it was ready:\n%s%s", code, m.stdout, m.stderr)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("est mock did not start:\n%s%s", m.stdout, m.stderr)
		}
	}
	report := m.stdout.String()
	match := estMockServerURL.FindStringSubmatch(report)
	if match == nil {
		t.Fatalf("startup report lacks the server URL:\n%s", report)
	}
	m.url = match[1]
	if match := estMockSRPURL.FindStringSubmatch(report); match != nil {
		m.srpURL = match[1]
	}
	return m
}

// TestESTMock checks est mock with a TLS-SRP port and the sign-in failures that TLS-SRP reports.
func TestESTMock(t *testing.T) {
	usePassword(t, "")
	dir := t.TempDir()
	passwordFile, caOut := filepath.Join(dir, "password.txt"), filepath.Join(dir, "ca.pem")
	writeFile(t, passwordFile, []byte(estTestPassword+"\n"))
	m := startESTMock(t, "--listen", "127.0.0.1:0", "--srp-listen", "127.0.0.1:0", "--user", estTestUser,
		"--password-file", passwordFile, "--ca-out", caOut)
	if m.srpURL == "" {
		t.Fatalf("startup report lacks the TLS-SRP URL:\n%s", m.stdout)
	}
	caCert := readCert(t, caOut)
	sum := sha256.Sum256(caCert.Raw)
	report := m.stdout.String()
	for _, want := range []string{hex.EncodeToString(sum[:]), "--server " + m.srpURL + " --srp --user " + estTestUser, "--tls-ca-cert " + caOut} {
		if !strings.Contains(report, want) {
			t.Errorf("startup report lacks %q:\n%s", want, report)
		}
	}

	srp := func(extra ...string) []string {
		return append([]string{"est", "csrattrs", "--server", m.srpURL, "--srp", "--password-file", passwordFile}, extra...)
	}
	code, doc := runJSON(t, "est", "enroll", "--server", m.srpURL, "--srp", "--user", estTestUser, "--password-file", passwordFile,
		"--subject", "CN=srp", "--cert-out", filepath.Join(dir, "srp.pem"), "--key-out", filepath.Join(dir, "srp.key"))
	if code != exitOK || get(doc, "exchange.0.tls.srpUser") != estTestUser || get(doc, "exchange.0.tls.version") != "TLS 1.2" {
		t.Errorf("TLS-SRP enroll: exit %d, connection %v, error %v", code, get(doc, "exchange.0"), doc["error"])
	}
	code, doc = runJSON(t, "est", "reenroll", "--server", m.srpURL, "--srp", "--user", estTestUser, "--password-file", passwordFile,
		"--cert", filepath.Join(dir, "srp.pem"), "--cert-out", filepath.Join(dir, "srp2.pem"), "--key-out", filepath.Join(dir, "srp2.key"))
	if code != exitOK {
		t.Errorf("TLS-SRP reenroll: exit %d, error %v", code, doc["error"])
	}
	code, doc = runJSON(t, "est", "cacerts", "--server", m.srpURL, "--srp", "--user", estTestUser, "--password-file", passwordFile)
	if code != exitOK || get(doc, "result.verified") != "srp" {
		t.Errorf("TLS-SRP cacerts: exit %d, result %v", code, doc["result"])
	}

	wrongFile := filepath.Join(dir, "wrong.txt")
	writeFile(t, wrongFile, []byte("wrong"))
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"wrong password", []string{"est", "csrattrs", "--server", m.srpURL, "--srp", "--user", estTestUser, "--password-file", wrongFile},
			exitRejected, "Check --user and the password."},
		{"unknown user", srp("--user", "nobody"), exitRejected, "The server has no TLS-SRP user of this name. Check --user."},
		{"HTTPS port", []string{"est", "csrattrs", "--server", m.url, "--srp", "--user", estTestUser, "--password-file", passwordFile},
			exitTransport, "The server did not accept TLS-SRP."},
		{"TLS-SRP port", []string{"est", "csrattrs", "--server", m.srpURL, "--tls-ca-cert", caOut},
			exitTransport, "If this is a TLS-SRP port, sign in with --srp."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, doc := runJSON(t, tt.args...)
			if code != tt.code || !strings.Contains(text(get(doc, "error.hint")), tt.want) {
				t.Errorf("exit %d, error %v, want %d and %q", code, doc["error"], tt.code, tt.want)
			}
		})
	}

	if code := m.stop(t); code != exitOK {
		t.Errorf("est mock exited with %d:\n%s", code, m.stderr)
	}
	output := m.stdout.String()
	for _, want := range []string{"POST  simpleenroll  CN=srp  ->  HTTP 200  certs-only", "TLS-SRP sign-in from", "srptls: wrong SRP password", "Mock CA stopped"} {
		if !strings.Contains(output, want) {
			t.Errorf("log lacks %q:\n%s", want, output)
		}
	}
}

// TestESTMockErrors checks that est mock refuses bad settings and leaves no CA file behind.
func TestESTMockErrors(t *testing.T) {
	usePassword(t, "")
	dir := t.TempDir()
	caOut := filepath.Join(dir, "ca.pem")
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--user", ""}, "--user must not be empty"},
		{[]string{"--retry-after", "-1"}, "--retry-after must not be negative"},
		{[]string{"--password-file", "-", "--token-file", "-"}, "--password-file and --token-file cannot both read standard input"},
		{[]string{"--listen", "127.0.0.1:0", "--srp-listen", "127.0.0.1:99999", "--ca-out", caOut}, "--srp-listen"},
	}
	for _, tt := range tests {
		code, _, errOut := run(t, append([]string{"est", "mock"}, tt.args...)...)
		if code != exitLocal || !errorContains(errOut, tt.want) {
			t.Errorf("%q: exit %d:\n%s", tt.args, code, errOut)
		}
	}
	if _, err := os.Stat(caOut); !os.IsNotExist(err) {
		t.Error("a failed start left the CA file")
	}
}

// TestESTUsageErrors checks flag combinations that the EST commands refuse before connecting.
func TestESTUsageErrors(t *testing.T) {
	usePassword(t, "")
	dir := t.TempDir()
	out := func(name string) string { return filepath.Join(dir, name) }
	server := []string{"--server", "https://127.0.0.1:1"}
	tests := []struct {
		args []string
		want string
	}{
		{append([]string{"est", "enroll", "--cert-out", out("c"), "--key-out", out("k")}, server...), "--subject or --san is required"},
		{append([]string{"est", "enroll", "--subject", "CN=x", "--csr", out("r"), "--cert-out", out("c")}, server...), "--subject and --san cannot change"},
		{append([]string{"est", "enroll", "--csr", out("r"), "--tls-unique", "--cert-out", out("c")}, server...), "--tls-unique signs the request again"},
		{append([]string{"est", "enroll", "--subject", "CN=x", "--new-key", out("k"), "--cert-out", out("c"), "--key-out", out("k2")}, server...),
			"--key-out is only used with a new key"},
		{append([]string{"est", "enroll", "--subject", "CN=x", "--cert-out", out("c")}, server...), "--key-out is required"},
		{append([]string{"est", "reenroll", "--cert", out("c0"), "--cert-out", out("c"), "--key-out", out("k")}, server...),
			"renewing without --key needs --user or --token"},
		{append([]string{"est", "csrattrs", "--srp"}, server...), "--srp needs --user"},
		{append([]string{"est", "csrattrs", "--srp", "--user", "u", "--tls-ca-cert", out("ca")}, server...), "none of the others can be"},
		{append([]string{"est", "csrattrs", "--srp", "--user", "u", "--cert", out("c"), "--key", out("k")}, server...), "Leave out --key"},
		{append([]string{"est", "cacerts", "--bootstrap", "--srp", "--user", "u"}, server...), "none of the others can be"},
		// A sign-in would reach the unchecked server, and the cacerts request needs none.
		{append([]string{"est", "cacerts", "--bootstrap", "--user", "u"}, server...), "none of the others can be"},
		{append([]string{"est", "cacerts", "--bootstrap", "--password-file", out("p")}, server...), "none of the others can be"},
		{append([]string{"est", "cacerts", "--bootstrap", "--token"}, server...), "none of the others can be"},
		{append([]string{"est", "cacerts", "--bootstrap", "--token-file", out("t")}, server...), "none of the others can be"},
		{append([]string{"est", "csrattrs", "--password-file", out("p")}, server...), "--password-file needs --user"},
		{append([]string{"est", "csrattrs", "--token", "--user", "u"}, server...), "none of the others can be"},
		{append([]string{"est", "csrattrs", "--token-file", out("t"), "--user", "u", "--password-file", out("p")}, server...), "none of the others can be"},
		{append([]string{"est", "csrattrs", "--token-file", "-", "--cert", out("c"), "--key", out("k"), "--key-password-file", "-"}, server...),
			"--token-file and --key-password-file cannot both read standard input"},
		{append([]string{"est", "csrattrs", "--token"}, server...), "no token: use --token-file"},
		{[]string{"est", "csrattrs", "--server", "https://127.0.0.1:1", "--timeout", "0s"}, "--timeout must be positive"},
		{[]string{"est", "csrattrs", "--server", "https://127.0.0.1:1", "--profile", "loose"}, "invalid --profile"},
		{[]string{"est", "csrattrs", "--server", "http://127.0.0.1:1"}, "is not an https URL"},
	}
	for _, tt := range tests {
		code, _, errOut := run(t, tt.args...)
		if code != exitLocal || !errorContains(errOut, tt.want) {
			t.Errorf("%q: exit %d, want %q:\n%s", tt.args, code, tt.want, errOut)
		}
	}
}

// TestParseESTServer checks the accepted --server URLs.
func TestParseESTServer(t *testing.T) {
	good := []struct {
		url, host, label string
	}{
		{"https://est.example.com", "est.example.com:443", ""},
		{"https://est.example.com/", "est.example.com:443", ""},
		{"https://est.example.com:8443/.well-known/est", "est.example.com:8443", ""},
		{"https://est.example.com/.well-known/est/devices/", "est.example.com:443", "devices"},
		{"https://[::1]:9443/.well-known/est/a", "[::1]:9443", "a"},
	}
	for _, tt := range good {
		srv, err := parseESTServer(tt.url)
		if err != nil || srv.host != tt.host || srv.label != tt.label {
			t.Errorf("parseESTServer(%q) = %+v, %v, want host %s and label %q", tt.url, srv, err, tt.host, tt.label)
		}
	}
	bad := []struct {
		url, want string
	}{
		{"http://est.example.com", "not an https URL"},
		{"https://", "not an https URL"},
		{"est.example.com", "not an https URL"},
		{"https://user:pw@est.example.com", "Use --user"},
		{"https://est.example.com/?x=1", "query or fragment"},
		{"https://est.example.com/est", "is not /.well-known/est"},
		{"https://est.example.com/.well-known/est/a/b", "is not /.well-known/est"},
		{"https://est.example.com/.well-known/est/simpleenroll", "ends in the operation"},
	}
	for _, tt := range bad {
		if _, err := parseESTServer(tt.url); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("parseESTServer(%q) error %v, want %q", tt.url, err, tt.want)
		}
	}
}

// TestInspectAndLintESTFile checks inspect and lint on a file that holds a PKCS#10 request.
func TestInspectAndLintESTFile(t *testing.T) {
	isolateColorEnv(t)
	key, err := keys.Generate(keys.DefaultType)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "file"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "device.csr")
	writeFile(t, file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	code, doc := runJSON(t, "inspect", file)
	msg := get(doc, "result.messages.0")
	if code != exitOK || get(msg, "protocol") != protocolEST || get(msg, "direction") != "request" ||
		get(msg, "est.content") != "pkcs10" || get(msg, "requests.0.subject") != "CN=file" ||
		get(msg, "requests.0.popSignature") != checkValid || get(msg, "header") != nil {
		t.Errorf("inspect: exit %d, message %v", code, msg)
	}

	code, doc = runJSON(t, "lint", file)
	// lint checks responses, so a request alone leaves nothing to check.
	if code != exitLocal || get(doc, "result.checked") != float64(0) {
		t.Errorf("lint: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
}
