package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
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
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
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
	Confirmed   bool               `json:"confirmed"`
	Certificate *certificateJSON   `json:"certificate"`
	Chain       []*certificateJSON `json:"chain"`
	Saved       []string           `json:"saved"`
}

// revokeJSON is the result of revoke.
type revokeJSON struct {
	Certificate *certificateJSON `json:"certificate"`
	Reason      string           `json:"reason"`
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
