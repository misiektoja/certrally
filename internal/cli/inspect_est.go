package cli

import (
	"cmp"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	est "github.com/misiektoja/go-pki-est"
	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/cmpfile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// describeESTMessage describes an EST request or response.
func describeESTMessage(m cmpfile.Message) *messageReport {
	rec := m.EST
	r := &messageReport{json: messageJSON{
		Source:    m.Source,
		Protocol:  protocolEST,
		Direction: rec.Kind,
		Server:    m.Server,
		Size:      rec.Size,
		EST: &estMessageJSON{
			Operation:   rec.Operation,
			Method:      rec.Method,
			Path:        rec.Path,
			HTTPStatus:  rec.HTTPStatus,
			ContentType: rec.ContentType,
			Content:     rec.Content,
			RetryAfter:  rec.RetryAfter,
			Parts:       rec.Parts,
			Text:        rec.Text,
		},
	}}
	if !m.Time.IsZero() {
		t := m.Time.UTC()
		r.json.Time = &t
	}
	r.estExchange(r.json.EST)
	if rec.Problem != "" {
		r.problem("%s", rec.Problem)
	}
	if len(m.DER) == 0 {
		return r
	}
	switch rec.Content {
	case trace.ContentPKCS10:
		csr, err := x509.ParseCertificateRequest(m.DER)
		if err != nil {
			r.problem("The PKCS#10 request does not parse: %v", err)
			break
		}
		r.csr(csr)
	case trace.ContentCertsOnly, trace.ContentServerKeyGen:
		r.estCertificates(m.DER)
	case trace.ContentCSRAttrs:
		var attrs est.CSRAttrs
		if err := attrs.Unmarshal(m.DER); err != nil {
			r.problem("The CSR attributes do not decode: %v", err)
			break
		}
		var fields []ui.Field
		r.json.Attributes, fields = csrAttrsResult(attrs)
		if len(fields) == 0 {
			fields = []ui.Field{{Name: "Attributes", Value: valueNone}}
		}
		r.section("CSR attributes", fields...)
	}
	return r
}

// estExchange describes the HTTP exchange of a captured EST message. A file other than a capture
// has none.
func (r *messageReport) estExchange(e *estMessageJSON) {
	if e.Method == "" && e.HTTPStatus == 0 {
		return
	}
	request, status, retry := "", "", ""
	if e.Method != "" {
		request = ui.Sanitize(e.Method + " " + e.Path)
	}
	if e.HTTPStatus != 0 {
		status = strings.TrimSpace(fmt.Sprintf("%d %s", e.HTTPStatus, http.StatusText(e.HTTPStatus)))
	}
	if e.RetryAfter != nil {
		retry = (time.Duration(*e.RetryAfter) * time.Second).String()
	}
	parts := make([]string, 0, len(e.Parts))
	for _, part := range e.Parts {
		parts = append(parts, ui.Sanitize(cmp.Or(part.ContentType, "no content type"))+", "+count(part.Size, "byte", "bytes"))
	}
	text := ""
	if e.Text != "" {
		text = quoteText([]string{e.Text})
	}
	r.section("HTTP",
		ui.Field{Name: "Request", Value: request},
		ui.Field{Name: fieldStatus, Value: status},
		ui.Field{Name: "Content type", Value: ui.Sanitize(e.ContentType)},
		ui.Field{Name: "Parts", Value: strings.Join(parts, "; ")},
		ui.Field{Name: "Retry after", Value: retry},
		ui.Field{Name: "Server says", Value: text},
	)
}

// estCertificates describes the certificates of a certs-only message.
func (r *messageReport) estCertificates(der []byte) {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		r.problem("The certs-only message does not parse: %v", err)
		return
	}
	if len(p7.Certificates) == 0 {
		r.section("Certificates", ui.Field{Name: "Count", Value: valueNone})
	}
	for i, cert := range p7.Certificates {
		r.json.Certificates = append(r.json.Certificates, certificateResult(cert))
		r.section(fmt.Sprintf("Certificate %d", i+1), describeCertificate(cert)...)
	}
}
