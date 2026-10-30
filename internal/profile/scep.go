package profile

import (
	"bytes"
	"fmt"
	"mime"
	"net/http"
	"unicode"
)

// SCEPResponse holds what the SCEP rules check in a response.
type SCEPResponse struct {
	// Operation is the SCEP operation the response answers, such as "GetCACaps".
	Operation   string
	HTTPStatus  int
	ContentType string
	// Body is the response body. Only the GetCACaps rule reads it.
	Body []byte
	// Certificates counts the certificates of a GetCACert answer.
	Certificates int
	// MessageType names the pkiMessage of a PKIOperation answer, such as "CertRep". SenderNonce
	// reports whether it carries a senderNonce attribute.
	MessageType string
	SenderNonce bool
}

// scepContentTypes names the media type and the section of RFC 8894 that a successful answer to
// each operation has. A GetCACert answer with several certificates has its own type.
var scepContentTypes = map[string]struct{ mediaType, rule string }{
	"GetCACert":     {"application/x-x509-ca-cert", "RFC 8894 section 4.2.1.1"},
	"PKIOperation":  {"application/x-pki-message", "RFC 8894 section 4.3.1"},
	"GetNextCACert": {"application/x-x509-next-ca-cert", "RFC 8894 section 4.7.1"},
}

// CheckSCEP returns the rules of RFC 8894 that a SCEP response breaks. The go-pki-scep client
// accepts these deviations. Error answers are not checked unless they carry a CertRep, which some
// servers send with an HTTP error status.
func CheckSCEP(r SCEPResponse) []Finding {
	if len(r.Body) == 0 || (r.HTTPStatus != http.StatusOK && r.MessageType == "") {
		return nil
	}
	var findings []Finding
	add := func(rule, format string, args ...any) {
		text := fmt.Sprintf("The %s answer ", r.Operation) + fmt.Sprintf(format, args...)
		findings = append(findings, Finding{Text: text, Rule: rule})
	}
	if r.Operation == "GetCACaps" && bytes.ContainsFunc(r.Body, isStrayControl) {
		add("RFC 8894 section 3.5.2", "holds control characters, such as a NUL byte, besides the line breaks")
	}
	if want, ok := scepContentTypes[r.Operation]; ok {
		mediaType, _, _ := mime.ParseMediaType(r.ContentType)
		if r.Operation == "GetCACert" && r.Certificates > 1 {
			want.mediaType, want.rule = "application/x-x509-ca-ra-cert", "RFC 8894 section 4.2.1.2"
		}
		if mediaType != want.mediaType {
			got := r.ContentType
			if got == "" {
				got = "no content type"
			}
			add(want.rule, "has %s instead of %s", got, want.mediaType)
		}
	}
	if r.MessageType == "CertRep" && !r.SenderNonce {
		add("RFC 8894 section 3.2.1", "has no senderNonce attribute")
	}
	return findings
}

// isStrayControl reports whether r is a control character other than the line breaks that separate
// the capabilities.
func isStrayControl(r rune) bool {
	return unicode.IsControl(r) && r != '\n' && r != '\r'
}
