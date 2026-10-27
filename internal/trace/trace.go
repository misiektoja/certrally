// Package trace records the CMP or EST messages a client exchanges over HTTP, for the ladder view
// and for telling transport failures apart from protocol failures.
package trace

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/dn"
)

// Kind says what an Event records.
type Kind int

// Event kinds.
const (
	// Request is a message the client sent.
	Request Kind = iota
	// Response is an HTTP response the client received, CMP or not.
	Response
	// Failure is a request that got no HTTP response.
	Failure
	// Connect is a TLS connection the client opened.
	Connect
)

// Event is one step of an exchange.
type Event struct {
	Kind Kind
	// Time is when the request was sent or the response or failure arrived.
	Time time.Time
	// Elapsed is the round-trip time of a response or failure.
	Elapsed time.Duration
	// HTTPStatus and ContentType describe a response.
	HTTPStatus  int
	ContentType string
	// Size is the body size in bytes.
	Size int
	// DER is the body. It is nil when a response exceeded the size limit.
	DER []byte
	// Message summarizes the body when it parses as a PKIMessage.
	Message *Summary
	// EST summarizes an EST request or response. DER then holds the decoded message instead of the
	// body.
	EST *ESTSummary
	// TLS describes the connection of a Connect event.
	TLS *TLSInfo
	// Transport is set when Kind is Failure or when a response cannot carry CMP or EST, such as a
	// 404 page.
	Transport error
}

// Summary holds the fields of a PKIMessage that the ladder view and JSON output show.
type Summary struct {
	// Body is the body type, such as "ir", "ip" or "error".
	Body string
	// Nested lists the body types of the messages inside a nested body, such as the ir that a
	// registration authority forwards.
	Nested []string
	// Protection names the protection algorithm. It is "none" for an unprotected message.
	Protection string
	// Sender is the sender name in the header. It is peer-controlled text.
	Sender        string
	TransactionID []byte
	SenderKID     []byte
	// Status, FailInfo and StatusText come from the first status in ip, cp, kup, rp or error bodies.
	// They are peer-controlled text and must be sanitized before display.
	Status     string
	FailInfo   pkicmp.PKIFailureInfo
	StatusText []string
	// CheckAfter is the wait in seconds a pollRep asks for.
	CheckAfter int64
	// ExtraCerts counts the certificates in the extraCerts field.
	ExtraCerts int
}

// Label returns the body type, followed by the body types inside a nested message, such as
// "nested(ir)".
func (s *Summary) Label() string {
	if len(s.Nested) == 0 {
		return s.Body
	}
	return s.Body + "(" + strings.Join(s.Nested, ", ") + ")"
}

// Record is the JSON form of an Event, shared by JSON output and capture files. Byte strings in the
// header are hex. Peer-controlled text is kept as sent, because JSON escaping makes it safe.
type Record struct {
	// Kind is "request", "response" or "failure".
	Kind      string    `json:"kind"`
	Time      time.Time `json:"time"`
	ElapsedMS float64   `json:"elapsedMs,omitempty"`
	// HTTPStatus and ContentType describe a response.
	HTTPStatus  int    `json:"httpStatus,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Size        int    `json:"size"`
	// The following fields are set when the body parses as a PKIMessage.
	Body string `json:"body,omitempty"`
	// Nested lists the body types inside a nested message.
	Nested        []string `json:"nested,omitempty"`
	Protection    string   `json:"protection,omitempty"`
	Sender        string   `json:"sender,omitempty"`
	TransactionID string   `json:"transactionId,omitempty"`
	SenderKID     string   `json:"senderKid,omitempty"`
	Status        string   `json:"status,omitempty"`
	FailInfo      []string `json:"failInfo,omitempty"`
	StatusText    []string `json:"statusText,omitempty"`
	CheckAfter    int64    `json:"checkAfter,omitempty"`
	ExtraCerts    int      `json:"extraCerts,omitempty"`
	// The following fields describe EST requests and responses.
	Method       string `json:"method,omitempty"`
	Path         string `json:"path,omitempty"`
	Operation    string `json:"operation,omitempty"`
	Content      string `json:"content,omitempty"`
	Subject      string `json:"subject,omitempty"`
	Certificates int    `json:"certificates,omitempty"`
	RetryAfter   *int   `json:"retryAfter,omitempty"`
	Parts        []Part `json:"parts,omitempty"`
	Text         string `json:"text,omitempty"`
	// TLS describes the connection of a connect record.
	TLS *TLSInfo `json:"tls,omitempty"`
	// Problem says why a response cannot be a CMP or EST answer, why its EST message does not decode
	// or why a request got no response.
	Problem string `json:"problem,omitempty"`
	// DER is the body, encoded as base64. Capture files include it and JSON output leaves it out.
	DER []byte `json:"der,omitempty"`
}

// kindNames are the Record kinds of the event kinds.
var kindNames = map[Kind]string{Request: "request", Response: "response", Failure: "failure", Connect: "connect"}

// Record returns the JSON form of ev. withDER includes the message bytes.
func (ev Event) Record(withDER bool) Record {
	rec := Record{
		Kind:        kindNames[ev.Kind],
		Time:        ev.Time.UTC(),
		ElapsedMS:   float64(ev.Elapsed.Microseconds()) / 1000,
		HTTPStatus:  ev.HTTPStatus,
		ContentType: ev.ContentType,
		Size:        ev.Size,
	}
	if ev.Transport != nil {
		rec.Problem = ev.Transport.Error()
	}
	if withDER {
		rec.DER = ev.DER
	}
	if m := ev.Message; m != nil {
		rec.Body, rec.Nested, rec.Protection, rec.Sender = m.Body, m.Nested, m.Protection, m.Sender
		rec.TransactionID, rec.SenderKID = hex.EncodeToString(m.TransactionID), hex.EncodeToString(m.SenderKID)
		rec.Status, rec.StatusText, rec.CheckAfter, rec.ExtraCerts = m.Status, m.StatusText, m.CheckAfter, m.ExtraCerts
		rec.FailInfo = FailureNames(m.FailInfo)
	}
	if e := ev.EST; e != nil {
		rec.Method, rec.Path, rec.Operation, rec.Content = e.Method, e.Path, e.Operation, e.Content
		rec.Subject, rec.Certificates, rec.RetryAfter = e.Subject, e.Certificates, e.RetryAfter
		rec.Parts, rec.Text = e.Parts, e.Text
		if rec.Problem == "" {
			rec.Problem = e.Problem
		}
	}
	rec.TLS = ev.TLS
	return rec
}

// FailureNames lists the names of the failure bits set in f, in bit order.
func FailureNames(f pkicmp.PKIFailureInfo) []string {
	var names []string
	// Bit 0 of the ASN.1 BIT STRING is the most significant bit of PKIFailureInfo.
	for i := range 32 {
		bit := pkicmp.PKIFailureInfo(1) << (31 - i)
		if f&bit == 0 {
			continue
		}
		name := bit.String()
		if name == "" {
			name = fmt.Sprintf("unknown(%d)", i)
		}
		names = append(names, name)
	}
	return names
}

// maxBody matches the response size limit of the go-pki-cmp client, so the recorder never holds
// more than the client would accept.
const maxBody = 10 * 1024 * 1024

// Protocol says how a Recorder reads the messages it records.
type Protocol int

// Protocols.
const (
	// CMP reads bodies as DER-encoded PKIMessages (RFC 9811).
	CMP Protocol = iota
	// EST reads the base64 bodies of EST operations (RFC 7030).
	EST
)

// Recorder is an http.RoundTripper that records every exchange before passing the response on.
type Recorder struct {
	// Protocol says how bodies are read. The zero value reads CMP.
	Protocol Protocol
	// Next sends the requests. http.DefaultTransport is used when it is nil.
	Next http.RoundTripper
	// OnEvent, when set, is called with each event as it is recorded.
	OnEvent func(Event)
	// Inspect, when set, is called with each request and its response after both are recorded, if
	// the response holds a CMP message or is an EST answer. An error stops the response from
	// reaching the client.
	Inspect func(request, response Event) error

	mu     sync.Mutex
	events []Event
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// Wrap returns a transport that records into r and sends with next. It lets a client that builds its
// own transport, such as the go-pki-est client, record every exchange in one Recorder.
func (r *Recorder) Wrap(next http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) { return r.roundTrip(next, req) })
}

// RoundTrip records the request, sends it and records the response or failure.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.roundTrip(r.Next, req)
}

// roundTrip records the request, sends it with next and records the response or failure.
func (r *Recorder) roundTrip(next http.RoundTripper, req *http.Request) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		var err error
		reqBody, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	start := time.Now()
	reqEvent := Event{Kind: Request, Time: start, Size: len(reqBody)}
	if r.Protocol == EST {
		reqEvent.EST, reqEvent.DER = SummarizeESTRequest(req, reqBody)
	} else {
		reqEvent.DER, reqEvent.Message = reqBody, Summarize(reqBody)
	}
	r.add(reqEvent)

	if next == nil {
		next = http.DefaultTransport
	}
	resp, err := next.RoundTrip(req)
	now := time.Now()
	if err != nil {
		r.add(Event{Kind: Failure, Time: now, Elapsed: now.Sub(start), Transport: err})
		return nil, err
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	ev := Event{
		Kind:        Response,
		Time:        now,
		Elapsed:     now.Sub(start),
		HTTPStatus:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Size:        len(body),
	}
	switch {
	case readErr != nil:
		ev.Transport = fmt.Errorf("read response: %w", readErr)
	case len(body) > maxBody:
		ev.Transport = fmt.Errorf("response body is larger than %d bytes", maxBody)
	case r.Protocol == EST:
		ev.EST, ev.DER = SummarizeESTResponse(reqEvent.EST.Operation, resp, body)
		ev.Transport = estProblem(reqEvent.EST.Operation, resp.StatusCode, ev.ContentType)
	default:
		ev.DER = body
		ev.Transport = transportProblem(resp.StatusCode, ev.ContentType, len(body))
		ev.Message = Summarize(body)
	}
	r.add(ev)
	if r.Inspect != nil && ev.Transport == nil && (ev.Message != nil || ev.EST != nil) {
		if err := r.Inspect(reqEvent, ev); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
	}
	// The client reads the same bytes, followed by whatever the limit left unread.
	resp.Body = readCloser{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
	return resp, nil
}

// readCloser joins a replacement reader with the original body's Close.
type readCloser struct {
	io.Reader
	io.Closer
}

// transportProblem returns why a response cannot be a CMP answer. It follows the checks RFC 9811
// requires and the go-pki-cmp client applies. It returns nil if the response can be an answer.
func transportProblem(status int, contentType string, size int) error {
	class := status / 100
	if class != 2 && class != 4 && class != 5 {
		return fmt.Errorf("HTTP %d %s", status, http.StatusText(status))
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/pkixcmp" {
		if contentType == "" {
			contentType = "no content type"
		}
		return fmt.Errorf("HTTP %d %s with %s instead of a CMP message", status, http.StatusText(status), contentType)
	}
	if size == 0 && status != http.StatusOK {
		return fmt.Errorf("HTTP %d %s with an empty body", status, http.StatusText(status))
	}
	return nil
}

// Connected records a TLS connection the client opened.
func (r *Recorder) Connected(info TLSInfo) {
	r.add(Event{Kind: Connect, Time: time.Now(), TLS: &info})
}

// Failed records a request that failed before it was sent, such as one whose TLS handshake
// failed.
func (r *Recorder) Failed(err error, elapsed time.Duration) {
	r.add(Event{Kind: Failure, Time: time.Now(), Elapsed: elapsed, Transport: err})
}

// add stores an event and reports it.
func (r *Recorder) add(ev Event) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	if r.OnEvent != nil {
		r.OnEvent(ev)
	}
}

// Events returns a copy of the recorded events in order.
func (r *Recorder) Events() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// TransportError returns the transport problem of the last event. It returns nil if the last
// exchange delivered a CMP message or an EST answer or nothing was sent.
func (r *Recorder) TransportError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return nil
	}
	return r.events[len(r.events)-1].Transport
}

// Summarize parses der as a PKIMessage and returns its summary. It returns nil if der does not parse.
func Summarize(der []byte) *Summary {
	if len(der) == 0 {
		return nil
	}
	msg, err := pkicmp.ParsePKIMessage(der)
	if err != nil || msg.Body == nil {
		return nil
	}
	s := &Summary{
		Body:          msg.Body.Type.String(),
		Protection:    "none",
		TransactionID: msg.Header.TransactionID,
		SenderKID:     msg.Header.SenderKID,
		ExtraCerts:    len(msg.ExtraCerts),
	}
	if rdns := msg.Header.Sender.DirectoryName; len(rdns) > 0 {
		s.Sender = dn.String(rdns)
	}
	if alg := msg.Header.ProtectionAlg; alg != nil {
		s.Protection = AlgorithmName(alg.Algorithm)
	}
	if info, ok := statusOf(msg.Body); ok {
		s.Status = info.Status.String()
		s.FailInfo, s.StatusText = info.FailInfo, info.StatusString
	}
	switch msg.Body.Type {
	case pkicmp.BodyTypePollRep:
		if rep, err := msg.Body.PollRep(); err == nil && len(*rep) > 0 {
			s.CheckAfter = (*rep)[0].CheckAfter
		}
	case pkicmp.BodyTypeNested:
		if inner, err := msg.Body.Nested(); err == nil {
			for _, m := range inner {
				s.Nested = append(s.Nested, m.Body.Type.String())
			}
		}
	default:
	}
	return s
}

// statusOf returns the status a response body carries, if it has one.
func statusOf(body *pkicmp.PKIBody) (pkicmp.PKIStatusInfo, bool) {
	var rep *pkicmp.CertRepMessage
	var err error
	switch body.Type {
	case pkicmp.BodyTypeIP:
		rep, err = body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = body.KUP()
	case pkicmp.BodyTypeError:
		content, err := body.Error()
		if err != nil {
			return pkicmp.PKIStatusInfo{}, false
		}
		return content.PKIStatusInfo, true
	case pkicmp.BodyTypeRP:
		content, err := body.RP()
		if err != nil || len(content.Status) == 0 {
			return pkicmp.PKIStatusInfo{}, false
		}
		return content.Status[0], true
	default:
		return pkicmp.PKIStatusInfo{}, false
	}
	if err != nil || len(rep.Response) == 0 {
		return pkicmp.PKIStatusInfo{}, false
	}
	return rep.Response[0].Status, true
}

// algorithmNames maps the protection algorithms of RFC 9481 and ML-DSA to display names.
var algorithmNames = map[string]string{
	"1.2.840.113533.7.66.13":  "PBM",
	"1.2.840.113549.1.5.14":   "PBMAC1",
	"1.2.840.113549.1.1.5":    "RSA SHA-1",
	"1.2.840.113549.1.1.11":   "RSA SHA-256",
	"1.2.840.113549.1.1.12":   "RSA SHA-384",
	"1.2.840.113549.1.1.13":   "RSA SHA-512",
	"1.2.840.113549.1.1.10":   "RSA-PSS",
	"1.2.840.10045.4.1":       "ECDSA SHA-1",
	"1.2.840.10045.4.3.2":     "ECDSA SHA-256",
	"1.2.840.10045.4.3.3":     "ECDSA SHA-384",
	"1.2.840.10045.4.3.4":     "ECDSA SHA-512",
	"1.3.101.112":             "Ed25519",
	"1.3.101.113":             "Ed448",
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

// AlgorithmName returns a display name for a protection algorithm. Unknown algorithms keep their dotted OID.
func AlgorithmName(oid asn1.ObjectIdentifier) string {
	if name, ok := algorithmNames[oid.String()]; ok {
		return name
	}
	if alg, ok := compositemldsa.AlgorithmFromOID(oid); ok {
		return alg.String()
	}
	return oid.String()
}
