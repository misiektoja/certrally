package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/trace"
)

// The types in this file are the result members of the JSON document, documented in docs/json.md.
// Names are RFC 4514 strings, byte strings are hex and times are RFC 3339 in UTC.

// certificateJSON describes a certificate.
type certificateJSON struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	AltNames  []string  `json:"altNames,omitempty"`
	Key       string    `json:"key,omitempty"`
	SHA256    string    `json:"sha256"`
	PEM       string    `json:"pem"`
}

// certificateResult returns the JSON form of cert. It returns nil for a nil cert.
func certificateResult(cert *x509.Certificate) *certificateJSON {
	if cert == nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	c := &certificateJSON{
		Subject:   dn.Format(cert.RawSubject),
		Issuer:    dn.Format(cert.RawIssuer),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
		AltNames:  altNames(cert),
		SHA256:    hex.EncodeToString(sum[:]),
		PEM:       string(pemfile.EncodeCertificates([]*x509.Certificate{cert})),
	}
	if cert.SerialNumber != nil {
		c.Serial = strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))
	}
	if pub, err := keys.CertificateKey(cert); err == nil {
		c.Key = keys.Describe(pub)
	}
	return c
}

// certificatesResult returns the JSON form of certs, never nil.
func certificatesResult(certs []*x509.Certificate) []*certificateJSON {
	out := make([]*certificateJSON, 0, len(certs))
	for _, cert := range certs {
		out = append(out, certificateResult(cert))
	}
	return out
}

// enrollJSON is the result of enroll.
type enrollJSON struct {
	// Status is the PKIStatus of the certificate response, such as "accepted".
	Status string `json:"status,omitempty"`
	// Confirmed is false when the CA issued the certificate but the confirmation failed.
	Confirmed bool `json:"confirmed"`
	// ImplicitConfirm is true when the CA granted implicit confirmation, so no certConf was sent.
	ImplicitConfirm bool               `json:"implicitConfirm"`
	Certificate     *certificateJSON   `json:"certificate"`
	Chain           []*certificateJSON `json:"chain"`
	Saved           []string           `json:"saved"`
}

// revokeJSON is the result of revoke.
type revokeJSON struct {
	// Certificate is null when the certificate was named by issuer and serial number only.
	Certificate *certificateJSON `json:"certificate"`
	Issuer      string           `json:"issuer"`
	Serial      string           `json:"serial"`
	Reason      string           `json:"reason"`
	// InvalidityDate is the time sent with the request. It is absent when none was given.
	InvalidityDate time.Time `json:"invalidityDate,omitzero"`
}

// caCertsJSON is the result of cacerts.
type caCertsJSON struct {
	Certificates []*certificateJSON `json:"certificates"`
	Saved        []string           `json:"saved"`
}

// rootUpdateJSON is the result of cmp genm rootupdate. Update is null when no update is available.
type rootUpdateJSON struct {
	Update *rootUpdateCertsJSON `json:"update"`
	Saved  []string             `json:"saved"`
}

// rootUpdateCertsJSON holds the certificates of a root CA update.
type rootUpdateCertsJSON struct {
	NewWithNew *certificateJSON `json:"newWithNew"`
	NewWithOld *certificateJSON `json:"newWithOld,omitempty"`
	OldWithNew *certificateJSON `json:"oldWithNew,omitempty"`
}

// templateJSON is the result of cmp genm template. Template is null when the CA imposes nothing.
type templateJSON struct {
	Template *templateContentJSON `json:"template"`
}

// templateContentJSON describes a certificate request template. An attribute without a value in
// the subject is one the requester fills in.
type templateContentJSON struct {
	Subject    string          `json:"subject,omitempty"`
	Extensions []extensionJSON `json:"extensions,omitempty"`
	KeyTypes   []string        `json:"keyTypes,omitempty"`
}

// extensionJSON names a certificate extension.
type extensionJSON struct {
	OID      string `json:"oid"`
	Name     string `json:"name,omitempty"`
	Critical bool   `json:"critical,omitempty"`
}

// crlJSON is the result of cmp genm crl and crlupdate. CRL is null when the CA sent none.
type crlJSON struct {
	CRL   *crlContentJSON `json:"crl"`
	Saved []string        `json:"saved"`
}

// crlContentJSON describes a CRL.
type crlContentJSON struct {
	Issuer     string     `json:"issuer"`
	ThisUpdate time.Time  `json:"thisUpdate"`
	NextUpdate *time.Time `json:"nextUpdate,omitempty"`
	Number     string     `json:"number,omitempty"`
	Revoked    int        `json:"revoked"`
	// Signature is "valid", "invalid" or "unchecked" when no trusted certificate names the issuer.
	Signature string `json:"signature"`
	PEM       string `json:"pem"`
}

// rawGenMJSON is the result of cmp genm raw.
type rawGenMJSON struct {
	Items []infoItemJSON `json:"items"`
}

// infoItemJSON is one InfoTypeAndValue. Value is the DER value, encoded as base64.
type infoItemJSON struct {
	InfoType string `json:"infoType"`
	OID      string `json:"oid"`
	Value    []byte `json:"value,omitempty"`
}

// pingJSON is the result of ping.
type pingJSON struct {
	Sent       int      `json:"sent"`
	Answered   int      `json:"answered"`
	Sender     string   `json:"sender,omitempty"`
	Protection string   `json:"protection,omitempty"`
	RTTMS      *rttJSON `json:"rttMs,omitempty"`
	// Verified is set with --ca-cert. It tells whether every answer was signed by that CA.
	Verified *bool `json:"verified,omitempty"`
}

// rttJSON summarizes round-trip times in milliseconds.
type rttJSON struct {
	Min float64 `json:"min"`
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
}

// keygenJSON is the result of keygen.
type keygenJSON struct {
	KeyType   string   `json:"keyType"`
	Key       string   `json:"key"`
	PublicKey string   `json:"publicKey"`
	CSR       string   `json:"csr,omitempty"`
	Saved     []string `json:"saved"`
}

// keyTypesJSON is the result of keygen --list.
type keyTypesJSON struct {
	KeyTypes []string `json:"keyTypes"`
}

// pemString returns der as a PEM block of the given type.
func pemString(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// inspectJSON is the result of inspect.
type inspectJSON struct {
	Messages []messageJSON `json:"messages"`
}

// messageJSON describes one CMP or EST message. Body, header and protection describe a CMP message
// and est an EST message. The members after them appear only for the body types and EST contents
// that carry them.
type messageJSON struct {
	// Source locates the message, such as "run.jsonl:4" for line 4 of a capture file.
	Source string `json:"source"`
	// Protocol is "cmp" or "est".
	Protocol string `json:"protocol"`
	// Direction is "request" or "response".
	Direction string `json:"direction"`
	// Time and Server come from a capture file.
	Time       *time.Time      `json:"time,omitempty"`
	Server     string          `json:"server,omitempty"`
	Size       int             `json:"size"`
	Body       string          `json:"body,omitempty"`
	Header     *headerJSON     `json:"header,omitempty"`
	Protection *protectionJSON `json:"protection,omitempty"`
	EST        *estMessageJSON `json:"est,omitempty"`
	// Requests are the certificate requests of ir, cr, kur, p10cr and an EST PKCS#10 request.
	Requests []certRequestJSON `json:"requests,omitempty"`
	// Responses are the certificate responses of ip, cp and kup.
	Responses []certResponseJSON `json:"responses,omitempty"`
	CAPubs    []*certificateJSON `json:"caPubs,omitempty"`
	// Revocations are the entries of rr and rp.
	Revocations []revocationJSON `json:"revocations,omitempty"`
	// Confirmations are the entries of certConf.
	Confirmations []confirmationJSON `json:"confirmations,omitempty"`
	// Polls are the entries of pollReq and pollRep.
	Polls []pollJSON        `json:"polls,omitempty"`
	Error *errorContentJSON `json:"error,omitempty"`
	Items []infoItemJSON    `json:"items,omitempty"`
	// Challenges are the entries of popdecc. Answers are the numbers of popdecr in hex.
	Challenges []challengeJSON `json:"challenges,omitempty"`
	Answers    []string        `json:"answers,omitempty"`
	// Nested lists the body types of the messages in a nested body.
	Nested     []string           `json:"nested,omitempty"`
	ExtraCerts []*certificateJSON `json:"extraCerts,omitempty"`
	// Certificates are those of an EST certs-only message or serverkeygen response.
	Certificates []*certificateJSON `json:"certificates,omitempty"`
	// Attributes are the EST CSR attributes.
	Attributes []csrAttrJSON `json:"attributes,omitempty"`
	// Problems lists the parts of the message that could not be decoded.
	Problems []string `json:"problems,omitempty"`
}

// estMessageJSON describes an EST request or response. Only content is known for a file other than
// a capture.
type estMessageJSON struct {
	Operation   string `json:"operation,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	HTTPStatus  int    `json:"httpStatus,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	// Content is "pkcs10", "certs-only", "csrattrs" or "serverkeygen". It is absent without a body.
	Content    string       `json:"content,omitempty"`
	RetryAfter *int         `json:"retryAfter,omitempty"`
	Parts      []trace.Part `json:"parts,omitempty"`
	// Text is the text of an error response.
	Text string `json:"text,omitempty"`
}

// headerJSON describes a PKIHeader.
type headerJSON struct {
	PVNO          int        `json:"pvno"`
	Sender        string     `json:"sender"`
	Recipient     string     `json:"recipient"`
	MessageTime   *time.Time `json:"messageTime,omitempty"`
	TransactionID string     `json:"transactionId,omitempty"`
	SenderNonce   string     `json:"senderNonce,omitempty"`
	RecipNonce    string     `json:"recipNonce,omitempty"`
	SenderKID     string     `json:"senderKid,omitempty"`
	RecipKID      string     `json:"recipKid,omitempty"`
	FreeText      []string   `json:"freeText,omitempty"`
	// GeneralInfo names the info types in generalInfo.
	GeneralInfo []string `json:"generalInfo,omitempty"`
	CertProfile string   `json:"certProfile,omitempty"`
}

// protectionJSON describes the protection of a message.
type protectionJSON struct {
	// Algorithm is the protection algorithm. It is "none" for an unprotected message.
	Algorithm string `json:"algorithm"`
	// Check is "valid", "invalid" or "unchecked". It is absent for an unprotected message. A MAC
	// is unchecked without the shared secret.
	Check string `json:"check,omitempty"`
	// Signer is the subject of the certificate whose signature verifies.
	Signer string `json:"signer,omitempty"`
	// Trusted tells with --ca-cert whether the signer chains to those certificates.
	Trusted *bool `json:"trusted,omitempty"`
	// Problem says why the protection is invalid or unchecked.
	Problem string `json:"problem,omitempty"`
}

// certRequestJSON describes a certificate request.
type certRequestJSON struct {
	// CertReqID is absent for p10cr, which has none.
	CertReqID  *int64          `json:"certReqId,omitempty"`
	Subject    string          `json:"subject,omitempty"`
	Key        string          `json:"key,omitempty"`
	Extensions []extensionJSON `json:"extensions,omitempty"`
	// POP is the kind of proof-of-possession: "signature", "raVerified", "keyEncipherment",
	// "keyAgreement" or "none".
	POP string `json:"pop"`
	// POPSignature is "valid", "invalid" or "unchecked" for a signature proof.
	POPSignature string `json:"popSignature,omitempty"`
	// POPProblem says why the proof is invalid or unchecked.
	POPProblem string `json:"popProblem,omitempty"`
	// OldCert is the certificate a key update request replaces.
	OldCert *certIDJSON `json:"oldCert,omitempty"`
}

// certIDJSON names a certificate by issuer and serial number.
type certIDJSON struct {
	Issuer string `json:"issuer"`
	Serial string `json:"serial"`
}

// statusJSON is a PKIStatusInfo.
type statusJSON struct {
	Status     string   `json:"status"`
	FailInfo   []string `json:"failInfo,omitempty"`
	StatusText []string `json:"statusText,omitempty"`
}

// certResponseJSON describes a certificate response.
type certResponseJSON struct {
	CertReqID int64 `json:"certReqId"`
	statusJSON
	Certificate *certificateJSON `json:"certificate,omitempty"`
	// Encrypted is set when the CA sent the certificate encrypted.
	Encrypted bool `json:"encrypted,omitempty"`
}

// revocationJSON is an entry of rr or rp. Issuer and Serial are absent in rp when the CA does not
// name the certificate. Reason appears in rr and the status in rp.
type revocationJSON struct {
	Issuer string `json:"issuer,omitempty"`
	Serial string `json:"serial,omitempty"`
	Reason string `json:"reason,omitempty"`
	*statusJSON
}

// confirmationJSON is an entry of certConf. A missing status means the certificate is accepted.
type confirmationJSON struct {
	CertReqID int64  `json:"certReqId"`
	CertHash  string `json:"certHash"`
	HashAlg   string `json:"hashAlg,omitempty"`
	*statusJSON
}

// challengeJSON is an entry of popdecc. OWF is absent from every challenge but the first, which
// names the one-way function for all of them.
type challengeJSON struct {
	OWF               string `json:"owf,omitempty"`
	Witness           string `json:"witness"`
	EncryptedRandSize int    `json:"encryptedRandSize"`
}

// pollJSON is an entry of pollReq or pollRep. CheckAfter and Reason appear in pollRep.
type pollJSON struct {
	CertReqID  int64    `json:"certReqId"`
	CheckAfter *int64   `json:"checkAfter,omitempty"`
	Reason     []string `json:"reason,omitempty"`
}

// errorContentJSON is the content of an error body.
type errorContentJSON struct {
	statusJSON
	ErrorCode    int      `json:"errorCode,omitempty"`
	ErrorDetails []string `json:"errorDetails,omitempty"`
}

// lintJSON is the result of lint.
type lintJSON struct {
	// Checked counts the responses checked and Skipped those without a request before them.
	Checked  int               `json:"checked"`
	Skipped  int               `json:"skipped"`
	Findings []lintFindingJSON `json:"findings"`
}

// lintFindingJSON is a rule that a response breaks.
type lintFindingJSON struct {
	Source string `json:"source"`
	Body   string `json:"body"`
	Text   string `json:"text"`
	Rule   string `json:"rule"`
}

// estCACertsJSON is the result of est cacerts.
type estCACertsJSON struct {
	Certificates []*certificateJSON `json:"certificates"`
	Saved        []string           `json:"saved"`
	// Verified says how the certificates were checked: "tls", "srp", "fingerprint", "confirmed" or "none".
	Verified string `json:"verified"`
	// TLSIssued reports whether these certificates issued the TLS certificate of the server.
	TLSIssued *bool `json:"tlsIssued,omitempty"`
}

// estEnrollJSON is the result of est enroll, est reenroll and est serverkeygen.
type estEnrollJSON struct {
	Certificate *certificateJSON `json:"certificate"`
	// Key names the type of the new key. It is absent when the command certified a key it was given.
	Key   string   `json:"key,omitempty"`
	Saved []string `json:"saved"`
}

// csrAttrsJSON is the result of est csrattrs.
type csrAttrsJSON struct {
	Attributes []csrAttrJSON `json:"attributes"`
}

// csrAttrJSON is one entry of the CSR attributes. Values is absent for an entry that is only an
// OID.
type csrAttrJSON struct {
	OID    string   `json:"oid"`
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values,omitempty"`
}
