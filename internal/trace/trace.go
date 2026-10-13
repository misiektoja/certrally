// Package trace records the CMP messages a client exchanges over HTTP, for the ladder view and for
// telling transport failures apart from protocol failures.
package trace

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
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
	// Transport is set when a response cannot carry CMP, such as a 404 page, or when Kind is Failure.
	Transport error
}

// Summary holds the fields of a PKIMessage that the ladder view and JSON output show.
type Summary struct {
	// Body is the body type, such as "ir", "ip" or "error".
	Body string
	// Protection names the protection algorithm, or "none".
	Protection string
	// Sender is the sender name in the header. It is peer-controlled text.
	Sender        string
	TransactionID []byte
	SenderKID     []byte
	// Status, FailInfo and StatusText come from the first status in ip, cp, kup, rp or error bodies.
	// They are peer-controlled text and must be sanitized before display.
	Status     string
	FailInfo   string
	StatusText []string
	// CheckAfter is the wait in seconds a pollRep asks for.
	CheckAfter int64
	// ExtraCerts counts the certificates in the extraCerts field.
	ExtraCerts int
}

// maxBody matches the response size limit of the go-pki-cmp client, so the recorder never holds
// more than the client would accept.
const maxBody = 10 * 1024 * 1024

// Recorder is an http.RoundTripper that records every exchange before passing the response on.
type Recorder struct {
	// Next sends the requests. http.DefaultTransport is used when it is nil.
	Next http.RoundTripper
	// OnEvent, when set, is called with each event as it is recorded.
	OnEvent func(Event)

	mu     sync.Mutex
	events []Event
}

// RoundTrip records the request, sends it and records the response or failure.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
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
	r.add(Event{Kind: Request, Time: start, Size: len(reqBody), DER: reqBody, Message: Summarize(reqBody)})

	next := r.Next
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
	default:
		ev.DER = body
		ev.Transport = transportProblem(resp.StatusCode, ev.ContentType, len(body))
		ev.Message = Summarize(body)
	}
	r.add(ev)
	// The client reads the same bytes, followed by whatever the limit left unread.
	resp.Body = readCloser{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
	return resp, nil
}

// readCloser joins a replacement reader with the original body's Close.
type readCloser struct {
	io.Reader
	io.Closer
}

// transportProblem returns why a response cannot be a CMP answer, following the checks RFC 9811
// requires and the go-pki-cmp client applies, or nil if it can be one.
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

// TransportError returns the transport problem of the last event, or nil if the last exchange
// delivered a CMP message or nothing was sent.
func (r *Recorder) TransportError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return nil
	}
	return r.events[len(r.events)-1].Transport
}

// Summarize parses der as a PKIMessage and returns its summary, or nil if it does not parse.
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
		var name pkix.Name
		name.FillFromRDNSequence(&rdns)
		s.Sender = name.String()
	}
	if alg := msg.Header.ProtectionAlg; alg != nil {
		s.Protection = AlgorithmName(alg.Algorithm)
	}
	if info, ok := statusOf(msg.Body); ok {
		s.Status = info.Status.String()
		if info.FailInfo != 0 {
			s.FailInfo = info.FailInfo.String()
		}
		s.StatusText = info.StatusString
	}
	if msg.Body.Type == pkicmp.BodyTypePollRep {
		if rep, err := msg.Body.PollRep(); err == nil && len(*rep) > 0 {
			s.CheckAfter = (*rep)[0].CheckAfter
		}
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

// AlgorithmName returns a display name for a protection algorithm, or its dotted OID.
func AlgorithmName(oid asn1.ObjectIdentifier) string {
	if name, ok := algorithmNames[oid.String()]; ok {
		return name
	}
	if alg, ok := compositemldsa.AlgorithmFromOID(oid); ok {
		return alg.String()
	}
	return oid.String()
}
