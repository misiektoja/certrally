package trace

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/misiektoja/go-pkcs7"
)

// SCEP operations, as in SCEPSummary.Operation (RFC 8894 section 4). GetCACertChain is not in the
// RFC, but some CAs serve it.
const (
	SCEPGetCACaps      = "GetCACaps"
	SCEPGetCACert      = "GetCACert"
	SCEPGetCACertChain = "GetCACertChain"
	SCEPGetNextCACert  = "GetNextCACert"
	SCEPPKIOperation   = "PKIOperation"
)

// scepPKIMessageType is the media type of a pkiMessage (RFC 8894 section 4.3).
const scepPKIMessageType = "application/x-pki-message"

// SCEP message types and statuses, as in SCEPSummary.MessageType and SCEPSummary.Status.
const (
	SCEPCertRep = "CertRep"
	SCEPSuccess = "SUCCESS"
	SCEPFailure = "FAILURE"
	SCEPPending = "PENDING"
)

// SCEPSummary holds the fields of a SCEP request or response that the ladder view and JSON output
// show. Text, the CA name, the transaction ID and the capabilities come from the peer and must be
// sanitized before display.
type SCEPSummary struct {
	// Method, Operation and CAName describe a request. CAName is the message parameter of an
	// operation other than PKIOperation.
	Method    string
	Operation string
	CAName    string
	// MessageType, TransactionID, the nonces, Status and FailInfo are the attributes of a
	// pkiMessage. MessageType and FailInfo are names, such as "PKCSReq" and "badRequest".
	MessageType    string
	TransactionID  string
	SenderNonce    []byte
	RecipientNonce []byte
	Status         string
	FailInfo       string
	// Digest names the digest of the pkiMessage signature, such as "SHA-256". Cipher names the content
	// cipher of its pkiEnvelope, such as "AES-128-CBC". It is empty without an envelope.
	Digest string
	Cipher string
	// Capabilities lists the keywords of a GetCACaps answer.
	Capabilities []string
	// Certificates counts the certificates of a GetCACert, GetCACertChain or GetNextCACert answer.
	Certificates int
	// RetryAfter is the wait in seconds that the Retry-After header asks for. It is nil without a
	// valid header.
	RetryAfter *int
	// Text is the human-readable text of an error response.
	Text string
	// Problem says why the message does not decode.
	Problem string
}

// Label returns the message type of a pkiMessage, or else the operation.
func (s *SCEPSummary) Label() string {
	if s.MessageType != "" {
		return s.MessageType
	}
	return s.Operation
}

// The signed attributes of a pkiMessage (RFC 8894 section 3.2.1).
var (
	oidSCEPMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
)

// scepMessageTypes names the messageType values of RFC 8894 section 3.2.1.2.
var scepMessageTypes = map[string]string{
	"3":  SCEPCertRep,
	"17": "RenewalReq",
	"18": "UpdateReq",
	"19": "PKCSReq",
	"20": "CertPoll",
	"21": "GetCert",
	"22": "GetCRL",
}

// scepStatuses names the pkiStatus values of RFC 8894 section 3.2.1.3.
var scepStatuses = map[string]string{"0": SCEPSuccess, "2": SCEPFailure, "3": SCEPPending}

// scepFailInfos names the failInfo values of RFC 8894 section 3.2.1.4.
var scepFailInfos = map[string]string{
	"0": "badAlg",
	"1": "badMessageCheck",
	"2": "badRequest",
	"3": "badTime",
	"4": "badCertId",
}

// digestNames names the digest algorithms a pkiMessage signature uses.
var digestNames = map[string]string{
	"1.2.840.113549.2.5":     "MD5",
	"1.3.14.3.2.26":          "SHA-1",
	"2.16.840.1.101.3.4.2.4": "SHA-224",
	"2.16.840.1.101.3.4.2.1": "SHA-256",
	"2.16.840.1.101.3.4.2.2": "SHA-384",
	"2.16.840.1.101.3.4.2.3": "SHA-512",
	"1.2.840.113549.1.1.5":   "SHA-1",
	"1.2.840.113549.1.1.11":  "SHA-256",
	"1.2.840.113549.1.1.13":  "SHA-512",
}

// SummarizeSCEPRequest summarizes a SCEP request and returns the pkiMessage it carries, if any.
func SummarizeSCEPRequest(req *http.Request, body []byte) (*SCEPSummary, []byte) {
	query := req.URL.Query()
	s := &SCEPSummary{Method: req.Method, Operation: query.Get("operation")}
	if s.Operation != SCEPPKIOperation {
		s.CAName = query.Get("message")
		return s, nil
	}
	der := body
	if req.Method == http.MethodGet {
		// A query decodes "+" as a space, which a client that does not escape base64 sends.
		message := strings.ReplaceAll(query.Get("message"), " ", "+")
		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			s.Problem = "the message parameter is not base64: " + err.Error()
			return s, nil
		}
		der = decoded
	} else if decoded, ok := base64Body(body); ok {
		der = decoded
	}
	s.pkiMessage(der)
	return s, der
}

// base64Body decodes a POST body that a client sent as base64 rather than DER. It reports false for
// a DER body, which starts with a SEQUENCE tag.
func base64Body(body []byte) ([]byte, bool) {
	if len(body) == 0 || body[0] == 0x30 {
		return nil, false
	}
	der, err := decodeBase64(body)
	return der, err == nil
}

// SummarizeSCEPResponse summarizes the response to a SCEP operation and returns its body.
func SummarizeSCEPResponse(operation string, resp *http.Response, body []byte) (*SCEPSummary, []byte) {
	s := &SCEPSummary{Operation: operation, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	if resp.StatusCode != http.StatusOK {
		mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		switch {
		// Some servers send a PENDING or FAILURE CertRep with an HTTP error status, such as 202 or 400.
		case operation == SCEPPKIOperation && mediaType == scepPKIMessageType && len(body) > 0:
			s.pkiMessage(body)
		case mediaType == "text/html":
			s.Text = htmlText(body)
		case isErrorType(mediaType):
			s.Text = errorText(body)
		}
		return s, body
	}
	if len(body) == 0 {
		return s, nil
	}
	switch operation {
	case SCEPGetCACaps:
		s.Capabilities = capabilityKeywords(body)
	case SCEPGetCACert, SCEPGetCACertChain:
		s.caCertificates(body)
	case SCEPGetNextCACert:
		p7, err := parsePKCS7(body)
		if err != nil {
			s.Problem = "the answer is not a PKCS#7 message: " + err.Error()
			break
		}
		s.Certificates = len(p7.Certificates)
		s.Digest = signatureDigest(p7)
	case SCEPPKIOperation:
		s.pkiMessage(body)
	}
	return s, body
}

// htmlHidden matches the HTML elements whose text a browser does not show in the page. Go regular
// expressions have no back references, so a closing tag of another of these elements also ends a
// match, which only shortens the page text.
var htmlHidden = regexp.MustCompile(`(?is)<(head|script|style)\b.*?</(?:head|script|style)\s*>`)

// htmlTag matches an HTML tag or comment.
var htmlTag = regexp.MustCompile(`(?s)<!--.*?-->|<[^>]*>`)

// htmlText returns the text of an HTML error page, as some SCEP servers send, with white space
// collapsed. It is the text of the page body, or of the whole page when the body has none.
func htmlText(body []byte) string {
	text := func(page string) string {
		return strings.Join(strings.Fields(html.UnescapeString(htmlTag.ReplaceAllString(page, " "))), " ")
	}
	visible := text(htmlHidden.ReplaceAllString(string(body), " "))
	if visible == "" {
		visible = text(string(body))
	}
	return errorText([]byte(visible))
}

// capabilityKeywords splits a GetCACaps answer into its keywords. RFC 8894 section 3.5.2 separates
// them with line breaks. Control characters such as a trailing NUL byte are dropped here and
// reported by the profile.
func capabilityKeywords(body []byte) []string {
	var caps []string
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
		if line != "" {
			caps = append(caps, line)
		}
	}
	return caps
}

// caCertificates counts the certificates of a GetCACert or GetCACertChain answer, which is one
// certificate or a certificate-only SignedData.
func (s *SCEPSummary) caCertificates(body []byte) {
	if p7, err := parsePKCS7(body); err == nil {
		s.Certificates = len(p7.Certificates)
		return
	}
	if _, err := parseCertificate(body); err != nil {
		s.Problem = "the answer is neither a certificate nor a PKCS#7 message: " + err.Error()
		return
	}
	s.Certificates = 1
}

// pkiMessage reads the attributes of a pkiMessage without verifying its signature, which needs
// the keys that only the client or server holds.
func (s *SCEPSummary) pkiMessage(der []byte) {
	p7, err := parsePKCS7(der)
	if err != nil {
		s.Problem = "the message is not a PKCS#7 message: " + err.Error()
		return
	}
	s.Digest = signatureDigest(p7)
	var messageType, status, failInfo, transactionID string
	if err := p7.UnmarshalSignedAttribute(oidSCEPMessageType, &messageType); err != nil {
		s.Problem = "the message has no messageType attribute"
		return
	}
	s.MessageType = nameOr(scepMessageTypes, messageType, "messageType ")
	if p7.UnmarshalSignedAttribute(oidSCEPTransactionID, &transactionID) == nil {
		s.TransactionID = transactionID
	}
	var nonce []byte
	if p7.UnmarshalSignedAttribute(oidSCEPSenderNonce, &nonce) == nil {
		s.SenderNonce = nonce
	}
	nonce = nil
	if p7.UnmarshalSignedAttribute(oidSCEPRecipientNonce, &nonce) == nil {
		s.RecipientNonce = nonce
	}
	if p7.UnmarshalSignedAttribute(oidSCEPPKIStatus, &status) == nil {
		s.Status = nameOr(scepStatuses, status, "pkiStatus ")
	}
	if p7.UnmarshalSignedAttribute(oidSCEPFailInfo, &failInfo) == nil {
		s.FailInfo = nameOr(scepFailInfos, failInfo, "failInfo ")
	}
	if len(p7.Content) > 0 {
		if envelope, err := pkcs7.Parse(p7.Content); err == nil {
			if alg, err := envelope.ContentEncryptionAlgorithm(); err == nil {
				s.Cipher = alg.String()
			} else if errors.Is(err, pkcs7.ErrUnsupportedAlgorithm) {
				s.Cipher = "unknown"
			}
		}
	}
}

// SCEPFailInfoName names a failInfo value, or quotes it when RFC 8894 defines none.
func SCEPFailInfoName(value string) string {
	return nameOr(scepFailInfos, value, "failInfo ")
}

// nameOr returns the name of value, or prefix and the quoted value when it has none.
func nameOr(names map[string]string, value, prefix string) string {
	if name, ok := names[value]; ok {
		return name
	}
	return fmt.Sprintf("%s%q", prefix, value)
}

// signatureDigest names the digest of the first signature of p7. It returns "" without a signer.
func signatureDigest(p7 *pkcs7.PKCS7) string {
	if len(p7.Signers) == 0 {
		return ""
	}
	oid := p7.Signers[0].DigestAlgorithm.Algorithm
	if name, ok := digestNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// parseCertificate parses one DER or PEM certificate.
func parseCertificate(body []byte) (*x509.Certificate, error) {
	der := body
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		der = block.Bytes
	}
	return x509.ParseCertificate(der)
}

// parsePKCS7 parses a PKCS#7 message, retrying with the parser that accepts certificates whose
// authority key identifier is marked critical, as some SCEP products send.
func parsePKCS7(der []byte) (*pkcs7.PKCS7, error) {
	p7, err := pkcs7.Parse(der)
	if err == nil {
		return p7, nil
	}
	if legacy, lerr := pkcs7.ParseWithOptions(der, pkcs7.ParseOptions{LegacyCertificateParser: true}); lerr == nil {
		return legacy, nil
	}
	return nil, err
}

// scepProblem returns why a response cannot be an answer to a SCEP operation, such as a redirect,
// a wrong path or an empty answer to an operation that must return something. It returns nil if
// the response can be an answer, including an error the server sent.
func scepProblem(operation string, status int, contentType string, size int) error {
	class := status / 100
	if class != 2 && class != 4 && class != 5 {
		return fmt.Errorf("HTTP %d %s", status, http.StatusText(status))
	}
	// Servers built on go-pki-scep answer GetNextCACert with 404 while no CA key rollover is prepared,
	// so there it can come from the right path. scep nextca tells the two apart with GetCACert.
	if status == http.StatusNotFound && operation != SCEPGetNextCACert {
		return errors.New("HTTP 404 Not Found")
	}
	if status != http.StatusOK {
		return nil
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch {
	case mediaType == "text/html":
		return fmt.Errorf("HTTP 200 OK with %s instead of a SCEP answer", contentType)
	case size == 0 && (operation == SCEPGetCACert || operation == SCEPGetCACertChain || operation == SCEPPKIOperation):
		// Some CA products answer this way when the CA name is missing or unknown.
		return errors.New("HTTP 200 OK with an empty body")
	}
	return nil
}
