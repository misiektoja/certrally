// Package profile checks CMP responses against the rules of the Lightweight CMP Profile (RFC 9483)
// and RFC 9810 that the go-pki-cmp client relaxes for interoperability.
//
// The client already rejects a response with the wrong transaction ID, wrong nonces or a protection
// that does not verify. The rules here cover deviations that the client accepts.
package profile

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"slices"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Profile names.
const (
	// Compatible accepts a response that breaks a rule and reports each deviation as a warning.
	Compatible = "compatible"
	// Strict rejects a response that breaks a rule.
	Strict = "strict"
)

// Names lists the profiles. The first one is the default.
var Names = []string{Compatible, Strict}

// Finding is a rule that a response breaks.
type Finding struct {
	// Text describes the deviation.
	Text string
	// Rule names the section that states the rule, such as "RFC 9483 section 3.5".
	Rule string
}

// String returns the deviation followed by the rule as one sentence.
func (f Finding) String() string { return f.Text + " (" + f.Rule + ")." }

// Generic header and protection OIDs that the rules refer to.
var (
	oidImplicitConfirm = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 13}
	oidConfirmWaitTime = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 14}
	oidCertProfile     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 21}
	oidPBM             = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	oidPBMAC1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
)

// minNonceBytes is the shortest senderNonce RFC 9483 section 3.5 accepts.
const minNonceBytes = 16

// Check returns the rules that resp breaks as the answer to req. trusted are the certificates the
// client trusts. A new certificate issued by a self-signed certificate in trusted or caPubs needs no chain.
func Check(req, resp *pkicmp.PKIMessage, trusted []*x509.Certificate) []Finding {
	c := &checker{req: req, resp: resp, body: resp.Body.Type.String(), trusted: trusted}
	c.header()
	c.generalInfo()
	c.protection()
	c.extraCerts()
	c.content()
	return c.findings
}

// checker collects the findings for one response.
type checker struct {
	req, resp *pkicmp.PKIMessage
	// body is the response body type, such as "ip".
	body string
	// trusted are the certificates the client trusts.
	trusted  []*x509.Certificate
	findings []Finding
}

// add records a deviation. text continues "The <body> response".
func (c *checker) add(rule, format string, args ...any) {
	c.findings = append(c.findings, Finding{
		Text: fmt.Sprintf("The %s response ", c.body) + fmt.Sprintf(format, args...),
		Rule: rule,
	})
}

// rfc9483 names a section of RFC 9483.
func rfc9483(section string) string { return "RFC 9483 section " + section }

// header checks the protocol version and the sender nonce.
func (c *checker) header() {
	h := c.resp.Header
	if h.PVNO != pkicmp.PVNO2 && h.PVNO != pkicmp.PVNO3 {
		c.add(rfc9483("3.5"), "has pvno %d instead of 2 or 3", h.PVNO)
	}
	switch n := len(h.SenderNonce); {
	case n == 0:
		c.add(rfc9483("3.5"), "has no senderNonce")
	case n < minNonceBytes:
		c.add(rfc9483("3.5"), "has a senderNonce of %d bits instead of at least 128", 8*n)
	}
}

// generalInfo checks implicitConfirm, confirmWaitTime and certProfile in the header.
func (c *checker) generalInfo() {
	h := c.resp.Header
	implicit := hasInfo(h, oidImplicitConfirm)
	switch {
	case implicit && certRep(c.resp.Body) == nil:
		c.add(rfc9483("3.1"), "carries implicitConfirm, which only ip, cp and kup responses may carry")
	case implicit && !hasInfo(c.req.Header, oidImplicitConfirm):
		c.add("RFC 9810 section 5.1.1.1", "grants implicitConfirm, which the request did not ask for")
	}
	if hasInfo(h, oidConfirmWaitTime) {
		if implicit {
			c.add(rfc9483("3.1"), "carries both implicitConfirm and confirmWaitTime")
		}
		if !h.HasMessageTime() {
			c.add(rfc9483("3.1"), "carries confirmWaitTime without messageTime")
		}
	}
	if hasInfo(h, oidCertProfile) {
		c.add(rfc9483("3.1"), "carries certProfile, which only requests may carry")
	}
}

// protection checks that the response is protected like the request and names its signing key.
// Error messages are exempt from the first rule, because a CA signs them when it cannot check the
// MAC of the request.
func (c *checker) protection() {
	if c.resp.Header.ProtectionAlg == nil {
		return
	}
	signed := !isMAC(c.resp)
	if c.req.Header.ProtectionAlg != nil && signed == isMAC(c.req) && c.resp.Body.Type != pkicmp.BodyTypeError {
		if signed {
			c.add(rfc9483("3.2"), "is signed, but the request is MAC-protected")
		} else {
			c.add(rfc9483("3.2"), "is MAC-protected, but the request is signed")
		}
	}
	if signer := c.signer(); signed && signer != nil && len(signer.SubjectKeyId) > 0 && len(c.resp.Header.SenderKID) == 0 {
		c.add(rfc9483("3.1"), "has no senderKID, although its protection certificate has a subject key identifier")
	}
}

// extraCerts checks that the first signed response of an operation starts extraCerts with its
// protection certificate and that a new certificate comes with its chain.
func (c *checker) extraCerts() {
	signed := c.resp.Header.ProtectionAlg != nil && !isMAC(c.resp)
	// Later messages of an operation may leave out extraCerts. RFC 9483 section 3.6.4 only recommends
	// them for error messages.
	first := c.req.Body.Type != pkicmp.BodyTypeCertConf && c.req.Body.Type != pkicmp.BodyTypePollReq &&
		c.resp.Body.Type != pkicmp.BodyTypeError
	switch {
	case len(c.resp.ExtraCerts) == 0 && c.needsChain():
		c.add(rfc9483("3.3"), "carries no extraCerts, so the chain of the new certificate is missing")
	case len(c.resp.ExtraCerts) == 0 && signed && first:
		c.add(rfc9483("3.3"), "carries no extraCerts, so its protection certificate is missing")
	case signed && first && c.signer() == nil:
		c.add(rfc9483("3.3"), "does not start extraCerts with its protection certificate")
	}
}

// content checks the body content.
func (c *checker) content() {
	switch c.resp.Body.Type {
	case pkicmp.BodyTypeError:
		content, err := c.resp.Body.Error()
		if err != nil {
			return
		}
		if s := content.PKIStatusInfo.Status; s != pkicmp.StatusRejection && s != pkicmp.StatusWaiting {
			c.add(rfc9483("3.6.4"), "has status %s instead of rejection", s)
		}
	case pkicmp.BodyTypePKIConf:
		// The parser accepts an empty body in place of the NULL that PKIConfirmContent requires.
		raw := cryptobyte.String(c.resp.Body.Raw)
		var content cryptobyte.String
		var tag cbasn1.Tag
		if raw.ReadAnyASN1(&content, &tag) && content.Empty() {
			c.add("RFC 9810 section 5.3.17", "is empty instead of holding NULL")
		}
	default:
	}
}

// signer returns the first certificate in extraCerts when it can be the protection certificate:
// its subject matches the sender and its key identifier matches senderKID. It returns nil otherwise.
func (c *checker) signer() *x509.Certificate {
	if len(c.resp.ExtraCerts) == 0 {
		return nil
	}
	cert, err := c.resp.ExtraCerts[0].Parse()
	if err != nil {
		return nil
	}
	h := c.resp.Header
	if sender := h.Sender.DirectoryName; len(sender) > 0 {
		var subject pkix.RDNSequence
		if _, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil || subject.String() != sender.String() {
			return nil
		}
	}
	if len(h.SenderKID) > 0 && !bytes.Equal(h.SenderKID, cert.SubjectKeyId) {
		return nil
	}
	return cert
}

// isMAC reports whether a message is protected with a MAC rather than a signature.
func isMAC(m *pkicmp.PKIMessage) bool {
	alg := m.Header.ProtectionAlg
	return alg != nil && (alg.Algorithm.Equal(oidPBM) || alg.Algorithm.Equal(oidPBMAC1))
}

// hasInfo reports whether the header carries the generalInfo item oid.
func hasInfo(h pkicmp.PKIHeader, oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(h.GeneralInfo, func(item pkicmp.InfoTypeAndValue) bool {
		return item.InfoType.Equal(oid)
	})
}

// certRep returns the content of an ip, cp or kup body. It returns nil for other bodies.
func certRep(body *pkicmp.PKIBody) *pkicmp.CertRepMessage {
	var rep *pkicmp.CertRepMessage
	var err error
	switch body.Type {
	case pkicmp.BodyTypeIP:
		rep, err = body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = body.KUP()
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return rep
}

// needsChain reports whether an ip, cp or kup delivers a certificate whose chain belongs in
// extraCerts. RFC 9483 section 3.3 leaves self-signed certificates out of extraCerts, so a
// certificate issued by a self-signed CA that the client knows from caPubs or trusts has no chain to
// send. A certificate that does not parse counts as needing one.
func (c *checker) needsChain() bool {
	rep := certRep(c.resp.Body)
	if rep == nil {
		return false
	}
	roots := slices.Clone(c.trusted)
	for _, pub := range rep.CAPubs {
		if cert, err := pub.Parse(); err == nil {
			roots = append(roots, cert)
		}
	}
	return slices.ContainsFunc(rep.Response, func(r pkicmp.CertResponse) bool {
		s := r.Status.Status
		if r.CertifiedKeyPair == nil || (s != pkicmp.StatusAccepted && s != pkicmp.StatusGrantedWithMods) {
			return false
		}
		pub := r.CertifiedKeyPair.CertOrEncCert.Certificate
		if pub == nil {
			// An encrypted certificate cannot be inspected.
			return true
		}
		cert, err := pub.Parse()
		if err != nil {
			return true
		}
		return !slices.ContainsFunc(roots, func(root *x509.Certificate) bool { return issuedByRoot(cert, root) })
	})
}

// issuedByRoot reports whether root is self-signed and issued cert, judged by names and key
// identifiers. The client verifies the signature, so the check need not.
func issuedByRoot(cert, root *x509.Certificate) bool {
	if !bytes.Equal(root.RawSubject, root.RawIssuer) || !bytes.Equal(cert.RawIssuer, root.RawSubject) {
		return false
	}
	return len(cert.AuthorityKeyId) == 0 || len(root.SubjectKeyId) == 0 ||
		bytes.Equal(cert.AuthorityKeyId, root.SubjectKeyId)
}
