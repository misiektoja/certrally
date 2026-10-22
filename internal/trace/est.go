package trace

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/dn"
)

// estPrefix is the path prefix of every EST operation (RFC 7030 section 3.2.2).
const estPrefix = "/.well-known/est/"

// EST operations whose answers have a fixed content type.
const (
	opCACerts        = "cacerts"
	opSimpleEnroll   = "simpleenroll"
	opSimpleReenroll = "simplereenroll"
	opServerKeyGen   = "serverkeygen"
	opCSRAttrs       = "csrattrs"
)

// EST content names, as in ESTSummary.Content.
const (
	ContentPKCS10       = "pkcs10"
	ContentCertsOnly    = "certs-only"
	ContentCSRAttrs     = "csrattrs"
	ContentServerKeyGen = "serverkeygen"
)

// mediaPKCS7 is the media type of the PKCS#7 and CMS messages of EST.
const mediaPKCS7 = "application/pkcs7-mime"

// maxESTText bounds the error text kept from an EST response.
const maxESTText = 4096

// ESTSummary holds the fields of an EST request or response that the ladder view and JSON output
// show. Text comes from the peer and must be sanitized before display.
type ESTSummary struct {
	// Method and Path describe a request.
	Method string
	Path   string
	// Operation is the EST operation, such as "simpleenroll". Label is the CA label in the path.
	Operation string
	Label     string
	// Content names the decoded message: ContentPKCS10, ContentCertsOnly, ContentCSRAttrs or
	// ContentServerKeyGen. It is empty when there is none.
	Content string
	// Subject is the subject of a PKCS#10 request.
	Subject string
	// Certificates counts the certificates of a certs-only message.
	Certificates int
	// RetryAfter is the wait in seconds that the Retry-After header asks for. It is nil without a
	// valid header.
	RetryAfter *int
	// Parts lists the parts of a multipart response. Only their types and sizes are kept, because
	// one of them holds the private key of a serverkeygen response.
	Parts []Part
	// Text is the human-readable text of an error response.
	Text string
	// Problem says why the message does not decode.
	Problem string
}

// Part is one part of a multipart EST response.
type Part struct {
	ContentType string `json:"contentType"`
	Size        int    `json:"size"`
}

// TLSInfo describes a TLS connection.
type TLSInfo struct {
	// Version and CipherSuite are the negotiated names, such as "TLS 1.3".
	Version     string `json:"version"`
	CipherSuite string `json:"cipherSuite"`
	// Server is the subject of the server certificate. It is empty when the server sent none.
	Server string `json:"server,omitempty"`
	// SRPUser is the username of a TLS-SRP connection.
	SRPUser string `json:"srpUser,omitempty"`
	// ServerCertificates is the chain the server sent, leaf first.
	ServerCertificates []*x509.Certificate `json:"-"`
}

// TLSInfoFromState describes a connection from its state.
func TLSInfoFromState(cs tls.ConnectionState) TLSInfo {
	info := TLSInfo{
		Version:            tls.VersionName(cs.Version),
		CipherSuite:        tls.CipherSuiteName(cs.CipherSuite),
		ServerCertificates: cs.PeerCertificates,
	}
	if len(cs.PeerCertificates) > 0 {
		info.Server = dn.Format(cs.PeerCertificates[0].RawSubject)
	}
	return info
}

// estOperation splits an EST path into its operation and CA label.
func estOperation(path string) (operation, label string) {
	rest, ok := strings.CutPrefix(path, estPrefix)
	if !ok {
		return "", ""
	}
	if label, operation, ok := strings.CutLast(rest, "/"); ok {
		return operation, label
	}
	return rest, ""
}

// SummarizeESTRequest summarizes an EST request and returns its decoded PKCS#10 request, if any.
func SummarizeESTRequest(req *http.Request, body []byte) (*ESTSummary, []byte) {
	s := &ESTSummary{Method: req.Method, Path: req.URL.Path}
	s.Operation, s.Label = estOperation(req.URL.Path)
	if len(body) == 0 {
		return s, nil
	}
	der, err := decodeBase64(body)
	if err != nil {
		s.Problem = "the request body is not base64: " + err.Error()
		return s, nil
	}
	s.Content = ContentPKCS10
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		s.Subject = dn.Format(csr.RawSubject)
	} else {
		s.Problem = "the request is not a PKCS#10 request: " + err.Error()
	}
	return s, der
}

// SummarizeESTResponse summarizes the response to an EST operation and returns its decoded message.
// The DER of a serverkeygen response is its certificate part.
func SummarizeESTResponse(operation string, resp *http.Response, body []byte) (*ESTSummary, []byte) {
	s := &ESTSummary{Operation: operation, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	mediaType, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK {
		if isErrorType(mediaType) {
			s.Text = errorText(body)
		}
		return s, nil
	}
	switch mediaType {
	case mediaPKCS7:
		return s, s.certsOnly(body)
	case "application/csrattrs":
		der, err := decodeBase64(body)
		if err != nil {
			s.Problem = "the CSR attributes are not base64: " + err.Error()
			return s, nil
		}
		s.Content = ContentCSRAttrs
		return s, der
	case "multipart/mixed":
		return s, s.multipart(body, params["boundary"])
	}
	return s, nil
}

// certsOnly decodes a certs-only message, counts its certificates and returns its DER.
func (s *ESTSummary) certsOnly(body []byte) []byte {
	der, err := decodeBase64(body)
	if err != nil {
		s.Problem = "the certificates are not base64: " + err.Error()
		return nil
	}
	s.Content = ContentCertsOnly
	p7, err := pkcs7.Parse(der)
	if err != nil {
		s.Problem = "the certificates are not a PKCS#7 message: " + err.Error()
		return der
	}
	s.Certificates = len(p7.Certificates)
	return der
}

// multipart records the parts of a serverkeygen response and returns the DER of its certificate
// part. The key part is never decoded.
func (s *ESTSummary) multipart(body []byte, boundary string) []byte {
	s.Content = ContentServerKeyGen
	var der []byte
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.Problem = "the multipart response does not decode: " + err.Error()
			break
		}
		data, err := io.ReadAll(part)
		if err != nil {
			s.Problem = "the multipart response does not decode: " + err.Error()
			break
		}
		ctype := part.Header.Get("Content-Type")
		s.Parts = append(s.Parts, Part{ContentType: ctype, Size: len(data)})
		mediaType, params, _ := mime.ParseMediaType(ctype)
		if mediaType == mediaPKCS7 && params["smime-type"] != "server-generated-key" && der == nil {
			der = s.certsOnly(data)
			s.Content = ContentServerKeyGen
		}
	}
	return der
}

// decodeBase64 decodes an EST body. RFC 8951 has receivers ignore white space in base64.
func decodeBase64(body []byte) ([]byte, error) {
	compact := strings.Join(strings.Fields(string(body)), "")
	return base64.StdEncoding.DecodeString(compact)
}

// retryAfter returns the seconds a Retry-After value asks for, as seconds or an HTTP date. It
// returns nil for an absent or invalid value.
func retryAfter(value string) *int {
	if value == "" {
		return nil
	}
	secs, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		t, err := http.ParseTime(value)
		if err != nil {
			return nil
		}
		secs = int(time.Until(t).Round(time.Second).Seconds())
	}
	secs = max(secs, 0)
	return &secs
}

// isErrorType reports whether an EST error response of this media type carries text for a person.
// RFC 7030 section 4.2.3 calls a response without a content type a plain text message.
func isErrorType(mediaType string) bool {
	switch mediaType {
	case "", "text/plain", "application/json", "application/problem+json":
		return true
	default:
		return false
	}
}

// errorText returns the text of an error response, shortened to maxESTText bytes.
func errorText(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > maxESTText {
		text = strings.ToValidUTF8(text[:maxESTText], "")
	}
	return text
}

// estAnswerTypes are the media types of a successful answer to each operation.
var estAnswerTypes = map[string]string{
	opCACerts:        mediaPKCS7,
	opSimpleEnroll:   mediaPKCS7,
	opSimpleReenroll: mediaPKCS7,
	opServerKeyGen:   "multipart/mixed",
	opCSRAttrs:       "application/csrattrs",
}

// estProblem returns why a response cannot be an EST answer to operation, such as a redirect, a
// missing operation or a proxy error page. It returns nil if the response can be an answer,
// including an error the EST server sent.
func estProblem(operation string, status int, contentType string) error {
	class := status / 100
	if class != 2 && class != 4 && class != 5 {
		return fmt.Errorf("HTTP %d %s", status, http.StatusText(status))
	}
	// RFC 7030 section 4.5.2 lets a server answer csrattrs with 404 when it has no attributes. For
	// the other operations a 404 means a wrong path or CA label.
	if status == http.StatusNotFound && operation != opCSRAttrs {
		return errors.New("HTTP 404 Not Found")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = ""
	}
	notEST := func() error {
		if contentType == "" {
			contentType = "no content type"
		}
		return fmt.Errorf("HTTP %d %s with %s instead of an EST response", status, http.StatusText(status), contentType)
	}
	switch {
	case status == http.StatusOK:
		if want, ok := estAnswerTypes[operation]; ok && mediaType != want {
			return notEST()
		}
	case class == 2:
	case !isErrorType(mediaType) && mediaType != mediaPKCS7:
		// RFC 7030 section 4.2.3 also allows a CMC response as an error.
		return notEST()
	}
	return nil
}
