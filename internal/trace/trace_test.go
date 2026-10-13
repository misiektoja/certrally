package trace

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// message returns the DER encoding of an unprotected message with body.
func message(t *testing.T, body *pkicmp.PKIBody) []byte {
	t.Helper()
	der, err := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{
		Sender:    pkicmp.NewDirectoryName(pkix.Name{CommonName: "a"}),
		Recipient: pkicmp.NewDirectoryName(pkix.Name{CommonName: "b"}),
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// respond returns a transport that answers every request with the given status, type and body.
func respond(status int, contentType string, body []byte) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, r.Body)
		h := http.Header{}
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	}
}

// send posts body through r and returns what the caller reads from the response.
func send(t *testing.T, r *Recorder, body []byte) ([]byte, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://ca.test/cmp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// TestRecorderCMP checks that a CMP exchange is recorded and passed through unchanged.
func TestRecorderCMP(t *testing.T) {
	reqDER := message(t, pkicmp.NewPKIConfBody())
	respDER := message(t, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{
		Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailBadMessageCheck, StatusString: pkicmp.PKIFreeText{"no"},
	}}))
	var seen []Kind
	var forwarded []byte
	next := respond(400, "application/pkixcmp", respDER)
	r := &Recorder{
		Next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			forwarded, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(forwarded))
			return next(req)
		}),
		OnEvent: func(ev Event) { seen = append(seen, ev.Kind) },
	}
	got, err := send(t, r, reqDER)
	if err != nil || !bytes.Equal(got, respDER) || !bytes.Equal(forwarded, reqDER) {
		t.Fatalf("the exchange was altered: %v", err)
	}
	events := r.Events()
	if len(events) != 2 || len(seen) != 2 || seen[0] != Request || seen[1] != Response {
		t.Fatalf("events = %+v", events)
	}
	if m := events[0].Message; m == nil || m.Body != "pkiconf" || m.Protection != "none" || m.Sender != "CN=a" {
		t.Errorf("request summary = %+v", m)
	}
	m := events[1].Message
	if m == nil || m.Body != "error" || m.Status != "rejection" || m.FailInfo != pkicmp.FailBadMessageCheck || m.StatusText[0] != "no" {
		t.Errorf("response summary = %+v", m)
	}
	if r.TransportError() != nil {
		t.Errorf("a CMP error message counted as a transport problem: %v", r.TransportError())
	}
}

// TestRecorderTransport checks responses that cannot carry CMP and requests that got no response.
func TestRecorderTransport(t *testing.T) {
	tests := []struct {
		name string
		next http.RoundTripper
		want string
	}{
		{"not found", respond(404, "text/html", []byte("<html>")), "HTTP 404 Not Found with text/html"},
		{"wrong type", respond(200, "", []byte("x")), "no content type"},
		{"redirect", respond(302, "application/pkixcmp", nil), "HTTP 302"},
		{"empty error", respond(503, "application/pkixcmp", nil), "empty body"},
		{"no response", roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("refused") }), "refused"},
	}
	for _, tt := range tests {
		r := &Recorder{Next: tt.next}
		_, _ = send(t, r, []byte{0x30, 0})
		err := r.TransportError()
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: TransportError = %v, want %q", tt.name, err, tt.want)
		}
	}
}

// TestAlgorithmName checks known, composite and unknown protection algorithms.
func TestAlgorithmName(t *testing.T) {
	alg := compositemldsa.Algorithms()[0]
	tests := map[string]asn1.ObjectIdentifier{
		"PBMAC1":      {1, 2, 840, 113549, 1, 5, 14},
		"ML-DSA-65":   {2, 16, 840, 1, 101, 3, 4, 3, 18},
		alg.String():  alg.OID(),
		"1.2.3.4.5.6": {1, 2, 3, 4, 5, 6},
	}
	for want, oid := range tests {
		if got := AlgorithmName(oid); got != want {
			t.Errorf("AlgorithmName(%v) = %q, want %q", oid, got, want)
		}
	}
}

// TestSummarizeGarbage checks that bodies that are not PKIMessages have no summary.
func TestSummarizeGarbage(t *testing.T) {
	for _, der := range [][]byte{nil, {0x30, 0}, []byte("<html>")} {
		if s := Summarize(der); s != nil {
			t.Errorf("Summarize(%q) = %+v", der, s)
		}
	}
}

// TestSummarizeRevocation checks that the status of a revocation response is reported.
func TestSummarizeRevocation(t *testing.T) {
	m := Summarize(message(t, pkicmp.NewRPBody(&pkicmp.RevRepContent{Status: []pkicmp.PKIStatusInfo{{
		Status: pkicmp.StatusRejection, FailInfo: pkicmp.FailCertRevoked,
	}}})))
	if m == nil || m.Body != "rp" || m.Status != "rejection" || m.FailInfo != pkicmp.FailCertRevoked {
		t.Errorf("summary = %+v", m)
	}
}

// TestRecord checks the JSON form of a CMP response and of a failure.
func TestRecord(t *testing.T) {
	der := message(t, pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{
		Status:       pkicmp.StatusRejection,
		FailInfo:     pkicmp.FailBadMessageCheck | pkicmp.FailBadRequest,
		StatusString: pkicmp.PKIFreeText{"no"},
	}}))
	ev := Event{Kind: Response, Elapsed: 1500 * time.Microsecond, HTTPStatus: 400, Size: len(der), DER: der, Message: Summarize(der)}
	rec := ev.Record(false)
	if rec.Kind != "response" || rec.ElapsedMS != 1.5 || rec.Body != "error" || rec.Sender != "CN=a" || rec.DER != nil {
		t.Errorf("record = %+v", rec)
	}
	if strings.Join(rec.FailInfo, ",") != "badMessageCheck,badRequest" || rec.StatusText[0] != "no" {
		t.Errorf("status = %v %v", rec.FailInfo, rec.StatusText)
	}
	if want := hex.EncodeToString(ev.Message.TransactionID); rec.TransactionID != want || len(want) != 32 {
		t.Errorf("transactionId = %q", rec.TransactionID)
	}
	if !bytes.Equal(ev.Record(true).DER, der) {
		t.Error("withDER left out the message")
	}
	failure := Event{Kind: Failure, Transport: errors.New("refused")}.Record(true)
	if failure.Kind != "failure" || failure.Problem != "refused" || failure.Body != "" {
		t.Errorf("failure record = %+v", failure)
	}
}

// TestFailureNames checks bit order and the name of a bit that RFC 9810 does not define.
func TestFailureNames(t *testing.T) {
	got := FailureNames(pkicmp.FailBadAlg | pkicmp.FailSystemFailure | pkicmp.PKIFailureInfo(1))
	if strings.Join(got, ",") != "badAlg,systemFailure,unknown(31)" {
		t.Errorf("FailureNames = %v", got)
	}
	if FailureNames(0) != nil {
		t.Error("no bits should give no names")
	}
}
