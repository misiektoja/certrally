package cli

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pkcs7"

	"github.com/misiektoja/certrally/internal/cmpfile"
	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// describeSCEPMessage describes a captured SCEP request or response.
func describeSCEPMessage(m cmpfile.Message) *messageReport {
	rec := m.SCEP
	e := &scepMessageJSON{
		Operation:      rec.Operation,
		Method:         rec.Method,
		HTTPStatus:     rec.HTTPStatus,
		ContentType:    rec.ContentType,
		CAName:         rec.CAName,
		MessageType:    rec.MessageType,
		TransactionID:  rec.TransactionID,
		SenderNonce:    rec.SenderNonce,
		RecipientNonce: rec.RecipientNonce,
		Status:         rec.Status,
		Digest:         rec.Digest,
		Cipher:         rec.Cipher,
		Capabilities:   rec.Capabilities,
		RetryAfter:     rec.RetryAfter,
		Text:           rec.Text,
	}
	if len(rec.FailInfo) > 0 {
		e.FailInfo = rec.FailInfo[0]
	}
	r := &messageReport{json: messageJSON{
		Source:    m.Source,
		Protocol:  protocolSCEP,
		Direction: rec.Kind,
		Server:    m.Server,
		Size:      rec.Size,
		SCEP:      e,
	}}
	// A GET request carries its pkiMessage in the URL, so the size is that of the pkiMessage.
	if r.json.Size == 0 && m.Request {
		r.json.Size = len(m.DER)
	}
	if !m.Time.IsZero() {
		t := m.Time.UTC()
		r.json.Time = &t
	}
	r.scepExchange(e)
	if rec.Problem != "" {
		r.problem("%s", rec.Problem)
	}
	// Some servers send a CertRep with an HTTP error status, so a pkiMessage is decoded whatever the
	// status.
	if len(m.DER) == 0 || (rec.HTTPStatus >= http.StatusMultipleChoices && e.MessageType == "") {
		return r
	}
	switch {
	case e.MessageType != "":
		r.scepPKIMessage(m.DER)
	case e.Operation == trace.SCEPGetNextCACert:
		r.scepNextCACert(m.DER)
	case e.Operation == trace.SCEPGetCACert || e.Operation == trace.SCEPGetCACertChain:
		r.scepCertificates(m.DER)
	}
	return r
}

// scepExchange describes the HTTP exchange and the SCEP attributes of a captured SCEP message.
func (r *messageReport) scepExchange(e *scepMessageJSON) {
	request, status, retry, text := "", "", "", ""
	if e.Method != "" {
		request = ui.Sanitize(e.Method + " " + e.Operation)
	}
	if e.HTTPStatus != 0 {
		status = strings.TrimSpace(fmt.Sprintf("%d %s", e.HTTPStatus, http.StatusText(e.HTTPStatus)))
	}
	if e.RetryAfter != nil {
		retry = (time.Duration(*e.RetryAfter) * time.Second).String()
	}
	if e.Text != "" {
		text = quoteText([]string{e.Text})
	}
	r.section("HTTP",
		ui.Field{Name: fieldRequest, Value: request},
		ui.Field{Name: fieldStatus, Value: status},
		ui.Field{Name: "Content type", Value: ui.Sanitize(e.ContentType)},
		ui.Field{Name: fieldRetryAfter, Value: retry},
		ui.Field{Name: fieldServerSays, Value: text},
	)
	caps := make([]string, len(e.Capabilities))
	for i, c := range e.Capabilities {
		caps[i] = ui.Sanitize(c)
	}
	fields := []ui.Field{
		{Name: "CA name", Value: ui.Sanitize(e.CAName)},
		{Name: "Message type", Value: e.MessageType},
		{Name: fieldTransactionID, Value: ui.Sanitize(e.TransactionID)},
		{Name: fieldStatus, Value: e.Status},
		{Name: fieldFailInfo, Value: e.FailInfo},
		{Name: "Sender nonce", Value: e.SenderNonce},
		{Name: "Recipient nonce", Value: e.RecipientNonce},
		{Name: "Signed with", Value: e.Digest},
		{Name: "Encrypted with", Value: e.Cipher},
		{Name: "Capabilities", Value: strings.Join(caps, ", ")},
	}
	// GetCACert and GetCACaps requests without a CA name have no SCEP fields.
	if slices.ContainsFunc(fields, func(f ui.Field) bool { return f.Value != "" }) {
		r.section("SCEP", fields...)
	}
}

// scepPKIMessage describes the signer, the certificates and the encrypted content of a pkiMessage.
// The content is encrypted for its recipient, so it is not decoded.
func (r *messageReport) scepPKIMessage(der []byte) {
	p7, err := scepParsePKCS7(der)
	if err != nil {
		r.problem("The pkiMessage does not parse: %v", err)
		return
	}
	if len(p7.Content) > 0 {
		var fields []ui.Field
		if envelope, err := scepParsePKCS7(p7.Content); err != nil {
			r.problem("The pkiEnvelope does not parse: %v", err)
		} else if recipients, err := envelope.Recipients(); err != nil {
			r.problem("The pkiEnvelope does not list its recipients: %v", err)
		} else {
			for _, rcpt := range recipients {
				fields = append(fields, ui.Field{
					Name:  "Recipient",
					Value: "serial " + hexBytes(rcpt.SerialNumber.Bytes()) + " issued by " + dn.Format(rcpt.Issuer),
				})
			}
			fields = append(fields, ui.Field{Name: "Content", Value: "encrypted, " + count(len(p7.Content), "byte", "bytes")})
		}
		r.section("Envelope", fields...)
	}
	signer := p7.GetOnlySigner()
	for i, cert := range p7.Certificates {
		r.json.Certificates = append(r.json.Certificates, certificateResult(cert))
		heading := fmt.Sprintf("Certificate %d", i+1)
		if cert == signer {
			heading += " (signer)"
		}
		r.section(heading, describeCertificate(cert)...)
	}
}

// scepNextCACert describes the certificates of a GetNextCACert answer, a signed message whose
// content is a certs-only message.
func (r *messageReport) scepNextCACert(der []byte) {
	p7, err := scepParsePKCS7(der)
	if err != nil {
		r.problem("The GetNextCACert answer does not parse: %v", err)
		return
	}
	if signer := p7.GetOnlySigner(); signer != nil {
		r.section("Signer", describeCertificate(signer)...)
	}
	r.scepCertificates(p7.Content)
}

// scepCertificates describes a GetCACert or GetCACertChain answer: one DER certificate or a
// certs-only message.
func (r *messageReport) scepCertificates(der []byte) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		p7, perr := scepParsePKCS7(der)
		if perr != nil {
			r.problem("The answer is neither a certificate nor a certs-only message: %v", perr)
			return
		}
		certs = p7.Certificates
	}
	if len(certs) == 0 {
		r.section("Certificates", ui.Field{Name: "Count", Value: valueNone})
	}
	for i, cert := range certs {
		r.json.Certificates = append(r.json.Certificates, certificateResult(cert))
		r.section(fmt.Sprintf("Certificate %d", i+1), describeCertificate(cert)...)
	}
}

// scepParsePKCS7 parses a PKCS#7 message and retries with the legacy certificate parser, which
// accepts the certificates some SCEP products send.
func scepParsePKCS7(der []byte) (*pkcs7.PKCS7, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		if legacy, lerr := pkcs7.ParseWithOptions(der, pkcs7.ParseOptions{LegacyCertificateParser: true}); lerr == nil {
			return legacy, nil
		}
	}
	return p7, err
}
