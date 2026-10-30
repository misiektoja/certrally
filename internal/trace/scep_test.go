package trace

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/scepclient"
	"github.com/misiektoja/go-pki-scep/scepserver"

	"github.com/misiektoja/certrally/internal/scepca"
)

// scepEnrollRequest returns a PKCSReq for a new RSA key, signed with a self-signed certificate.
func scepEnrollRequest(t *testing.T) scepclient.EnrollRequest {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return scepclient.EnrollRequest{CSR: csr, SignerCertificate: cert, SignerKey: key, Digest: crypto.SHA1}
}

// TestRecorderSCEPEnroll checks that an enrollment against a SCEP server is recorded with the
// attributes of its pkiMessages and passed through unchanged.
func TestRecorderSCEPEnroll(t *testing.T) {
	ca, err := scepca.New(scepca.Options{RA: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ca.Handler(scepserver.Options{Capabilities: []string{"SHA-1", "DES3"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	r := &Recorder{Protocol: SCEP, Next: http.DefaultTransport}
	client, err := scepclient.New(srv.URL+"/scep", scepclient.Options{HTTPClient: &http.Client{Transport: r}, CAName: "Issuing"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := client.Enroll(ctx, certs, scepEnrollRequest(t)); err != nil || res.Status != scep.SUCCESS {
		t.Fatalf("enroll: %v, %v", err, res)
	}

	events := r.Events()
	var ops []string
	for _, ev := range events {
		if ev.Kind == Request {
			ops = append(ops, ev.SCEP.Method+" "+ev.SCEP.Label())
		}
	}
	// Without POSTPKIOperation the request travels in the URL.
	if want := []string{"GET GetCACert", "GET GetCACaps", "GET PKCSReq"}; !slices.Equal(ops, want) {
		t.Fatalf("requests %q, want %q", ops, want)
	}
	if got := events[0].SCEP.CAName; got != "Issuing" {
		t.Errorf("GetCACert CA name %q", got)
	}
	if got := events[1].SCEP; got.Certificates != 2 || events[1].ContentType != "application/x-x509-ca-ra-cert" {
		t.Errorf("GetCACert answer: %+v, %s", got, events[1].ContentType)
	}
	if got := events[3].SCEP.Capabilities; !slices.Equal(got, []string{"SHA-1", "DES3"}) {
		t.Errorf("capabilities %q", got)
	}
	checkSCEPPKIOperation(t, events[4], events[5])
}

// checkSCEPPKIOperation checks the recorded PKCSReq of TestRecorderSCEPEnroll and its CertRep.
func checkSCEPPKIOperation(t *testing.T, req, resp Event) {
	t.Helper()
	if req.SCEP.MessageType != "PKCSReq" || req.SCEP.Digest != "SHA-1" || req.SCEP.Cipher != "DES-EDE3-CBC" ||
		len(req.SCEP.TransactionID) != 40 || len(req.SCEP.SenderNonce) == 0 || len(req.DER) == 0 {
		t.Errorf("request: %+v, %d bytes", req.SCEP, len(req.DER))
	}
	if resp.Transport != nil || resp.SCEP.MessageType != SCEPCertRep || resp.SCEP.Status != SCEPSuccess ||
		resp.SCEP.TransactionID != req.SCEP.TransactionID || !bytes.Equal(resp.SCEP.RecipientNonce, req.SCEP.SenderNonce) {
		t.Errorf("response: %+v, %v", resp.SCEP, resp.Transport)
	}
	rec := resp.Record(false)
	if rec.MessageType != SCEPCertRep || rec.Status != SCEPSuccess || rec.Operation != SCEPPKIOperation || rec.DER != nil ||
		rec.Digest != "SHA-1" || rec.Cipher != "DES-EDE3-CBC" || rec.RecipientNonce == "" {
		t.Errorf("record: %+v", rec)
	}
}

// scepCall sends one SCEP GET or POST through r and returns the response event.
func scepCall(t *testing.T, r *Recorder, method, operation, message string, body []byte) Event {
	t.Helper()
	u := "http://scep.test/scep?operation=" + operation
	if message != "" {
		u += "&message=" + message
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, u, bytes.NewReader(body))
	} else {
		req, err = http.NewRequest(method, u, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	events := r.Events()
	return events[len(events)-1]
}

// TestRecorderSCEPResponses checks how SCEP answers other than a pkiMessage are recorded, including
// those of CA products that bend RFC 8894.
func TestRecorderSCEPResponses(t *testing.T) {
	tests := []struct {
		name, operation string
		status          int
		contentType     string
		retryAfter      string
		body            string
		problem         string
		text            string
		caps            []string
		retry           bool
	}{
		{name: "caps with NUL", operation: "GetCACaps", status: 200, contentType: "text/plain",
			body: "Renewal\nSHA-1\r\nDES3\n\x00", caps: []string{"Renewal", "SHA-1", "DES3"}},
		{name: "empty CA certificate", operation: "GetCACert", status: 200, problem: "HTTP 200 OK with an empty body"},
		{name: "empty chain", operation: "GetCACertChain", status: 200, problem: "HTTP 200 OK with an empty body"},
		{name: "empty PKIOperation", operation: "PKIOperation", status: 200, problem: "HTTP 200 OK with an empty body"},
		{name: "no next CA", operation: "GetNextCACert", status: 200},
		{name: "busy without Retry-After", operation: "PKIOperation", status: 503, contentType: "text/plain",
			body: "busy", text: "busy"},
		{name: "busy with Retry-After", operation: "PKIOperation", status: 503, retryAfter: "10", retry: true},
		{name: "wrong path", operation: "GetCACert", status: 404, contentType: "text/plain", body: "not found",
			problem: "HTTP 404 Not Found", text: "not found"},
		{name: "html page", operation: "GetCACert", status: 200, contentType: "text/html", body: "<html>",
			problem: "HTTP 200 OK with text/html instead of a SCEP answer"},
		{name: "redirect", operation: "GetCACert", status: 302, problem: "HTTP 302 Found"},
		{name: "refused", operation: "GetCACert", status: 400, contentType: "text/plain", body: "unknown CA", text: "unknown CA"},
		{name: "html error page", operation: "PKIOperation", status: 400, contentType: "text/html;charset=UTF-8",
			body: "<html><head><title>Error</title><style>p{}</style></head><body><p>No password\n in &quot;request&quot;.</p></body></html>",
			text: `No password in "request".`},
		{name: "html title only", operation: "GetCACert", status: 500, contentType: "text/html",
			body: "<html><head><title>Internal error</title></head><body></body></html>", text: "Internal error"},
	}
	for _, tt := range tests {
		h := http.Header{}
		if tt.contentType != "" {
			h.Set("Content-Type", tt.contentType)
		}
		if tt.retryAfter != "" {
			h.Set("Retry-After", tt.retryAfter)
		}
		r := &Recorder{Protocol: SCEP, Next: respondHeader(tt.status, h, []byte(tt.body))}
		ev := scepCall(t, r, http.MethodGet, tt.operation, "", nil)
		problem := ""
		if ev.Transport != nil {
			problem = ev.Transport.Error()
		}
		if problem != tt.problem || ev.SCEP.Text != tt.text || !slices.Equal(ev.SCEP.Capabilities, tt.caps) ||
			(ev.SCEP.RetryAfter != nil) != tt.retry {
			t.Errorf("%s: problem %q, text %q, caps %q, retry %v", tt.name, problem, ev.SCEP.Text, ev.SCEP.Capabilities, ev.SCEP.RetryAfter)
		}
	}
}

// TestRecorderSCEPCertRepWithErrorStatus checks that a CertRep sent with an HTTP error status is
// decoded, and that an error answer of another media type keeps its text.
func TestRecorderSCEPCertRepWithErrorStatus(t *testing.T) {
	ca, err := scepca.New(scepca.Options{PendingPolls: 1})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ca.Handler(scepserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	r := &Recorder{Protocol: SCEP, Next: http.DefaultTransport}
	client, err := scepclient.New(srv.URL+"/scep", scepclient.Options{HTTPClient: &http.Client{Transport: r}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	certs, err := client.GetCACert(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := client.Enroll(ctx, certs, scepEnrollRequest(t)); err != nil || res.Status != scep.PENDING {
		t.Fatalf("enroll: %v, %v", err, res)
	}
	events := r.Events()
	certRep := events[len(events)-1].DER

	tests := []struct {
		name, contentType string
		body              []byte
		status, text      string
		problem           bool
	}{
		{name: "PENDING CertRep", contentType: "application/x-pki-message", body: certRep, status: SCEPPending},
		{name: "damaged CertRep", contentType: "application/x-pki-message", body: []byte("not a pkiMessage"), problem: true},
		{name: "text", contentType: "text/plain", body: []byte("No password in request"), text: "No password in request"},
	}
	for _, tt := range tests {
		replay := &Recorder{Protocol: SCEP, Next: respondHeader(http.StatusAccepted, http.Header{"Content-Type": {tt.contentType}}, tt.body)}
		ev := scepCall(t, replay, http.MethodGet, SCEPPKIOperation, "", nil)
		if ev.HTTPStatus != http.StatusAccepted || ev.SCEP.Status != tt.status || ev.SCEP.Text != tt.text || (ev.SCEP.Problem != "") != tt.problem {
			t.Errorf("%s: HTTP %d, %+v", tt.name, ev.HTTPStatus, ev.SCEP)
		}
		if tt.status != "" && (ev.SCEP.MessageType != SCEPCertRep || ev.SCEP.TransactionID == "" || ev.Transport != nil) {
			t.Errorf("%s: %+v, %v", tt.name, ev.SCEP, ev.Transport)
		}
	}
}

// TestSummarizeSCEPRequest checks how the pkiMessage of a request is found in a GET or POST.
func TestSummarizeSCEPRequest(t *testing.T) {
	ca, err := scepca.New(scepca.Options{})
	if err != nil {
		t.Fatal(err)
	}
	enroll := scepEnrollRequest(t)
	msg, err := scep.NewCSRRequest(scep.PKCSReq, enroll.CSR, scep.RequestOptions{
		SignerCertificate: enroll.SignerCertificate,
		SignerKey:         enroll.SignerKey,
		Recipients:        []*x509.Certificate{ca.Certificate()},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(msg.Raw)
	// About 3 KiB of base64 practically always hold a "+".
	if !strings.Contains(encoded, "+") {
		t.Fatal("the encoded message holds no +, so the unescaped GET tests nothing")
	}
	tests := []struct {
		name   string
		method string
		query  string
		body   []byte
	}{
		{"escaped GET", http.MethodGet, url.QueryEscape(encoded), nil},
		// A client that does not escape base64 sends "+", which the query decodes as a space.
		{"unescaped GET", http.MethodGet, encoded, nil},
		{"DER POST", http.MethodPost, "", msg.Raw},
		{"base64 POST", http.MethodPost, "", []byte(encoded)},
	}
	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, "http://scep.test/scep?operation=PKIOperation&message="+tt.query, bytes.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		s, der := SummarizeSCEPRequest(req, tt.body)
		if s.Problem != "" || s.MessageType != "PKCSReq" || !bytes.Equal(der, msg.Raw) {
			t.Errorf("%s: %+v, %d bytes", tt.name, s, len(der))
		}
	}
	req, err := http.NewRequest(http.MethodGet, "http://scep.test/scep?operation=PKIOperation&message=%25%25", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := SummarizeSCEPRequest(req, nil); !strings.Contains(s.Problem, "base64") {
		t.Errorf("undecodable message: %+v", s)
	}
	req, err = http.NewRequest(http.MethodGet, "http://scep.test/scep?operation=GetCACert&message=Issuing+CA", nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := SummarizeSCEPRequest(req, nil); s.CAName != "Issuing CA" || s.Label() != "GetCACert" {
		t.Errorf("GetCACert: %+v", s)
	}
}

// TestSCEPFailInfoName checks the names of failInfo values.
func TestSCEPFailInfoName(t *testing.T) {
	for value, want := range map[string]string{"0": "badAlg", "2": "badRequest", "4": "badCertId", "9": `failInfo "9"`} {
		if got := SCEPFailInfoName(value); got != want {
			t.Errorf("%s: %q, want %q", value, got, want)
		}
	}
}
