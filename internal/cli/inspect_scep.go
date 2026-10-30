package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
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

// describeSCEPMessage describes a captured SCEP request or response and checks its signature with a.
func describeSCEPMessage(m cmpfile.Message, a *anchors) *messageReport {
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
		r.scepPKIMessage(m.DER, a, m.Time)
	case e.Operation == trace.SCEPGetNextCACert:
		r.scepNextCACert(m.DER, a, m.Time)
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

// scepPKIMessage describes the signature, the certificates and the encrypted content of a
// pkiMessage. The content is encrypted for its recipient, so it is not decoded. at is the time of
// the capture.
func (r *messageReport) scepPKIMessage(der []byte, a *anchors, at time.Time) {
	p7, err := scepParsePKCS7(der)
	if err != nil {
		r.problem("The pkiMessage does not parse: %v", err)
		return
	}
	signer := r.scepProtection(p7, a, at)
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
	for i, cert := range p7.Certificates {
		r.json.Certificates = append(r.json.Certificates, certificateResult(cert))
		heading := fmt.Sprintf("Certificate %d", i+1)
		if cert == signer {
			heading += " (signer)"
		}
		r.section(heading, describeCertificate(cert)...)
	}
}

// scepNextCACert describes the signature and the certificates of a GetNextCACert answer, a signed
// message whose content is a certs-only message. at is the time of the capture.
func (r *messageReport) scepNextCACert(der []byte, a *anchors, at time.Time) {
	p7, err := scepParsePKCS7(der)
	if err != nil {
		r.problem("The GetNextCACert answer does not parse: %v", err)
		return
	}
	if signer := r.scepProtection(p7, a, at); signer != nil {
		r.section("Signer", describeCertificate(signer)...)
	}
	r.scepCertificates(p7.Content)
}

// scepCertificates describes a GetCACert or GetCACertChain answer: one DER certificate or a
// certs-only message.
func (r *messageReport) scepCertificates(der []byte) {
	certs, err := scepParseCertificates(der)
	if err != nil {
		r.problem("The answer is neither a certificate nor a certs-only message: %v", err)
		return
	}
	if len(certs) == 0 {
		r.section("Certificates", ui.Field{Name: "Count", Value: valueNone})
	}
	for i, cert := range certs {
		r.json.Certificates = append(r.json.Certificates, certificateResult(cert))
		r.section(fmt.Sprintf("Certificate %d", i+1), describeCertificate(cert)...)
	}
}

// scepParseCertificates parses a GetCACert or GetCACertChain answer: one DER certificate or a
// certs-only message.
func scepParseCertificates(der []byte) ([]*x509.Certificate, error) {
	if certs, err := x509.ParseCertificates(der); err == nil {
		return certs, nil
	}
	p7, err := scepParsePKCS7(der)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}

// scepCACertificates returns the certificates of the GetCACert and GetCACertChain answers among
// msgs. Answers that do not parse are skipped, because inspect reports them on their own.
func scepCACertificates(msgs []cmpfile.Message) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, m := range msgs {
		rec := m.SCEP
		if rec == nil || m.Request || rec.HTTPStatus >= http.StatusMultipleChoices ||
			(rec.Operation != trace.SCEPGetCACert && rec.Operation != trace.SCEPGetCACertChain) {
			continue
		}
		if c, err := scepParseCertificates(m.DER); err == nil {
			certs = append(certs, c...)
		}
	}
	return certs
}

// scepProtection describes the signature of a signed SCEP message and checks it with a. The chain of
// the signer is checked at the time at, or at the current time when at is zero. It returns the signer
// certificate when it is found, whether or not the signature verifies.
//
// The signer certificate is looked up by issuer and serial number among the certificates of the
// message, the --ca-cert certificates and the GetCACert answers of the inputs, because some servers
// send CertReps without it. The signature check depends on neither trust nor time.
func (r *messageReport) scepProtection(p7 *pkcs7.PKCS7, a *anchors, at time.Time) *x509.Certificate {
	if len(p7.Signers) == 0 {
		r.protectionSection(protectionJSON{Algorithm: valueNone}, "")
		return nil
	}
	digest := ""
	if r.json.SCEP != nil {
		digest = r.json.SCEP.Digest
	}
	j := protectionJSON{
		Algorithm: scepSignatureAlgorithm(p7.Signers[0].DigestEncryptionAlgorithm.Algorithm, digest),
		Check:     checkUnchecked,
	}
	candidates := slices.Concat(a.caCerts, a.scepCerts)
	signer := scepSigner(p7, candidates)
	opts := pkcs7.VerifyOptions{SignerCertificates: candidates, AllowMD5: true}
	switch err := p7.Verify(opts); {
	case signer == nil:
		j.Problem = "neither the message, --ca-cert nor a GetCACert answer holds the signer certificate"
	case err == nil:
		j.Check, j.Signer = checkValid, dn.Format(signer.RawSubject)
		if len(a.caCerts) > 0 {
			pool := x509.NewCertPool()
			for _, cert := range a.caCerts {
				pool.AddCert(cert)
			}
			opts.Roots, opts.Intermediates, opts.CurrentTime = pool, a.scepCerts, at
			trusted := p7.Verify(opts) == nil
			j.Trusted = &trusted
		}
	// go-pkcs7 has no error value for algorithms it does not implement, so its message tells them apart.
	case strings.Contains(err.Error(), "unsupported"):
		j.Problem = strings.TrimPrefix(err.Error(), "pkcs7: ")
	default:
		j.Check, j.Problem = checkInvalid, strings.TrimPrefix(err.Error(), "pkcs7: ")
	}
	r.protectionSection(j, fieldSignature)
	return signer
}

// scepSigner returns the certificate of the first signer of p7 among its certificates and
// candidates. It returns nil when any signer has no certificate there.
func scepSigner(p7 *pkcs7.PKCS7, candidates []*x509.Certificate) *x509.Certificate {
	certs := slices.Concat(p7.Certificates, candidates)
	var first *x509.Certificate
	for i, s := range p7.Signers {
		id := s.IssuerAndSerialNumber
		k := slices.IndexFunc(certs, func(c *x509.Certificate) bool {
			return c.SerialNumber.Cmp(id.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, id.IssuerName.FullBytes)
		})
		if k < 0 {
			return nil
		}
		if i == 0 {
			first = certs[k]
		}
	}
	return first
}

// scepSignatureAlgorithm names the signature algorithm of a SignerInfo. Most SCEP messages name only
// the key type there, such as rsaEncryption or id-ecPublicKey, so the digest is added to it.
func scepSignatureAlgorithm(oid asn1.ObjectIdentifier, digest string) string {
	var name string
	switch {
	case oid.Equal(pkcs7.OIDEncryptionAlgorithmRSA):
		name = "RSA"
	case oid.Equal(oidECPublicKey):
		name = "ECDSA"
	default:
		return trace.AlgorithmName(oid)
	}
	return strings.TrimSpace(name + " " + digest)
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
