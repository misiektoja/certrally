package trace

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

// testCertificate returns a self-signed certificate for name.
func testCertificate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
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

// certsOnly returns the DER of a certs-only PKCS#7 message holding certs.
func certsOnly(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	p7, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return p7
}

// testCSR returns the DER of a PKCS#10 request for name.
func testCSR(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// b64 returns der as base64 broken into lines, as EST servers send it.
func b64(der []byte) []byte {
	s := base64.StdEncoding.EncodeToString(der)
	var out strings.Builder
	for len(s) > 64 {
		out.WriteString(s[:64] + "\r\n")
		s = s[64:]
	}
	out.WriteString(s)
	return []byte(out.String())
}

// estCall sends one EST request through r and returns what the caller reads from the response.
func estCall(t *testing.T, r *Recorder, method, path string, body []byte) ([]byte, error) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://est.test"+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/pkcs10")
	}
	resp, err := r.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// respondHeader returns a transport that answers with the given status, headers and body.
func respondHeader(status int, header http.Header, body []byte) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	}
}

// TestRecorderESTEnroll checks that an enrollment is recorded with decoded messages and passed
// through unchanged.
func TestRecorderESTEnroll(t *testing.T) {
	csr := testCSR(t, "device-42")
	p7 := certsOnly(t, testCertificate(t, "device-42"), testCertificate(t, "Example CA"))
	respBody := b64(p7)
	r := &Recorder{
		Protocol: EST,
		Next: respondHeader(200, http.Header{
			"Content-Type": {"application/pkcs7-mime; smime-type=certs-only"},
		}, respBody),
	}
	got, err := estCall(t, r, http.MethodPost, "/.well-known/est/ca1/simpleenroll", b64(csr))
	if err != nil || !bytes.Equal(got, respBody) {
		t.Fatalf("caller read %q, %v", got, err)
	}
	events := r.Events()
	if len(events) != 2 {
		t.Fatalf("recorded %d events", len(events))
	}
	req, resp := events[0], events[1]
	if req.EST == nil || req.EST.Operation != "simpleenroll" || req.EST.Label != "ca1" || req.EST.Method != "POST" ||
		req.EST.Content != "pkcs10" || req.EST.Subject != "CN=device-42" || !bytes.Equal(req.DER, csr) {
		t.Errorf("request: %+v", req.EST)
	}
	if resp.Transport != nil || resp.EST == nil || resp.EST.Content != "certs-only" || resp.EST.Certificates != 2 ||
		!bytes.Equal(resp.DER, p7) || resp.Size != len(respBody) {
		t.Errorf("response: %+v, %v", resp.EST, resp.Transport)
	}
	rec := resp.Record(false)
	if rec.Operation != "simpleenroll" || rec.Content != "certs-only" || rec.Certificates != 2 || rec.DER != nil {
		t.Errorf("record: %+v", rec)
	}
}

// TestRecorderESTResponses checks how EST answers other than a certificate are recorded.
func TestRecorderESTResponses(t *testing.T) {
	tests := []struct {
		name, path  string
		status      int
		contentType string
		retryAfter  string
		body        string
		problem     string
		text        string
		retry       int
	}{
		{name: "waiting", path: "simpleenroll", status: 202, retryAfter: "30", retry: 30},
		{name: "refused", path: "simpleenroll", status: 401, contentType: "text/plain", body: " bad password\n", text: "bad password"},
		{name: "no type", path: "simpleenroll", status: 400, body: "bad request", text: "bad request"},
		{name: "busy", path: "simpleenroll", status: 503, contentType: "text/plain", retryAfter: "60", body: "later", text: "later", retry: 60},
		{name: "no attributes", path: "csrattrs", status: 404, contentType: "text/plain", body: "none", text: "none"},
		{name: "empty attributes", path: "csrattrs", status: 204},
		{name: "wrong path", path: "simpleenroll", status: 404, contentType: "text/plain", body: "404 page not found",
			problem: "HTTP 404 Not Found", text: "404 page not found"},
		{name: "html page", path: "cacerts", status: 200, contentType: "text/html", body: "<html>",
			problem: "HTTP 200 OK with text/html instead of an EST response"},
		{name: "proxy error", path: "cacerts", status: 502, contentType: "text/html", body: "<html>",
			problem: "HTTP 502 Bad Gateway with text/html instead of an EST response"},
		{name: "redirect", path: "cacerts", status: 302, problem: "HTTP 302 Found"},
		{name: "wrong type", path: "csrattrs", status: 200, contentType: "application/pkcs7-mime",
			problem: "HTTP 200 OK with application/pkcs7-mime instead of an EST response"},
	}
	for _, tt := range tests {
		h := http.Header{}
		if tt.contentType != "" {
			h.Set("Content-Type", tt.contentType)
		}
		if tt.retryAfter != "" {
			h.Set("Retry-After", tt.retryAfter)
		}
		r := &Recorder{Protocol: EST, Next: respondHeader(tt.status, h, []byte(tt.body))}
		_, _ = estCall(t, r, http.MethodGet, "/.well-known/est/"+tt.path, nil)
		ev := r.Events()[1]
		problem := ""
		if ev.Transport != nil {
			problem = ev.Transport.Error()
		}
		retry := 0
		if ev.EST.RetryAfter != nil {
			retry = *ev.EST.RetryAfter
		}
		if problem != tt.problem || ev.EST.Text != tt.text || retry != tt.retry {
			t.Errorf("%s: problem %q, text %q, retry %d", tt.name, problem, ev.EST.Text, retry)
		}
	}
}

// TestRecorderESTUndecodable checks that a body that is not base64 is reported, not recorded.
func TestRecorderESTUndecodable(t *testing.T) {
	r := &Recorder{Protocol: EST, Next: respondHeader(200, http.Header{"Content-Type": {"application/pkcs7-mime"}}, []byte("%%%"))}
	_, _ = estCall(t, r, http.MethodGet, "/.well-known/est/cacerts", nil)
	ev := r.Events()[1]
	if ev.Transport != nil || ev.DER != nil || !strings.Contains(ev.EST.Problem, "base64") {
		t.Errorf("response: %+v, %v", ev.EST, ev.Transport)
	}
	if rec := ev.Record(true); !strings.Contains(rec.Problem, "base64") {
		t.Errorf("record problem %q", rec.Problem)
	}
}

// TestRecorderESTServerKeyGen checks that the private key of a serverkeygen response never reaches
// the record.
func TestRecorderESTServerKeyGen(t *testing.T) {
	p7 := certsOnly(t, testCertificate(t, "device-42"))
	secretKey := []byte("PRIVATE-KEY-BYTES")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	parts := []struct {
		ctype string
		data  []byte
	}{
		{"application/pkcs8", b64(secretKey)},
		{"application/pkcs7-mime; smime-type=certs-only", b64(p7)},
	}
	for _, part := range parts {
		pw, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {part.ctype}})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write(part.data)
	}
	_ = mw.Close()
	body := buf.Bytes()
	r := &Recorder{Protocol: EST, Next: respondHeader(200, http.Header{
		"Content-Type": {"multipart/mixed; boundary=" + mw.Boundary()},
	}, body)}
	got, err := estCall(t, r, http.MethodPost, "/.well-known/est/serverkeygen", b64(testCSR(t, "device-42")))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("caller read %d bytes, %v", len(got), err)
	}
	ev := r.Events()[1]
	if ev.Transport != nil || ev.EST.Content != "serverkeygen" || ev.EST.Certificates != 1 || !bytes.Equal(ev.DER, p7) {
		t.Fatalf("response: %+v, %v", ev.EST, ev.Transport)
	}
	if len(ev.EST.Parts) != 2 || ev.EST.Parts[0].ContentType != "application/pkcs8" ||
		ev.EST.Parts[1].ContentType != "application/pkcs7-mime; smime-type=certs-only" {
		t.Errorf("parts: %+v", ev.EST.Parts)
	}
	data, err := json.Marshal(ev.Record(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{string(secretKey), base64.StdEncoding.EncodeToString(secretKey)} {
		if strings.Contains(string(data), leak) {
			t.Errorf("record holds the private key: %s", data)
		}
	}
}

// TestRecorderWrap checks that a wrapped transport records into the recorder.
func TestRecorderWrap(t *testing.T) {
	r := &Recorder{Protocol: EST}
	rt := r.Wrap(respondHeader(200, http.Header{"Content-Type": {"application/pkcs7-mime"}}, b64(certsOnly(t, testCertificate(t, "CA")))))
	req, err := http.NewRequest(http.MethodGet, "https://est.test/.well-known/est/cacerts", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if events := r.Events(); len(events) != 2 || events[1].EST.Certificates != 1 {
		t.Errorf("events: %+v", events)
	}
}

// TestRecorderConnected checks the record of a TLS connection.
func TestRecorderConnected(t *testing.T) {
	cert := testCertificate(t, "est.test")
	r := &Recorder{Protocol: EST}
	var seen []Kind
	r.OnEvent = func(ev Event) { seen = append(seen, ev.Kind) }
	r.Connected(TLSInfoFromState(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{cert},
	}))
	if len(seen) != 1 || seen[0] != Connect {
		t.Fatalf("events: %v", seen)
	}
	rec := r.Events()[0].Record(false)
	if rec.Kind != "connect" || rec.TLS == nil || rec.TLS.Version != "TLS 1.3" ||
		rec.TLS.CipherSuite != "TLS_AES_128_GCM_SHA256" || rec.TLS.Server != "CN=est.test" {
		t.Errorf("record: %+v %+v", rec, rec.TLS)
	}
	if !r.Events()[0].TLS.ServerCertificates[0].Equal(cert) {
		t.Error("server certificate not kept")
	}
}

// TestRecorderFailed checks that a request that failed before it was sent counts as a transport
// failure.
func TestRecorderFailed(t *testing.T) {
	r := &Recorder{Protocol: EST}
	r.Failed(io.ErrUnexpectedEOF, time.Second)
	ev := r.Events()[0]
	if ev.Kind != Failure || ev.Elapsed != time.Second || !errors.Is(r.TransportError(), io.ErrUnexpectedEOF) {
		t.Errorf("event: %+v", ev)
	}
}
