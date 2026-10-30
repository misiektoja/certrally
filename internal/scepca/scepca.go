// Package scepca is a SCEP test CA that keeps its keys and everything it issues in memory. It backs
// certrally scep mock and the tests of the SCEP commands.
package scepca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/scepserver"
)

// validity is how long issued certificates are valid.
const validity = 365 * 24 * time.Hour

// oidSubjectAltName is copied from requests into issued certificates.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// Options configures a CA. The zero value issues every request at once.
type Options struct {
	// Name is the CA name that GetCACert must carry in its message parameter. Empty accepts any
	// name, including none.
	Name string

	// Challenge is the challenge password a PKCSReq must carry. Nil accepts any challenge.
	Challenge []byte

	// PendingPolls answers a new enrollment with PENDING and issues the certificate at this
	// CertPoll. Zero issues at once.
	PendingPolls int

	// RA makes a separate RA certificate decrypt requests and sign answers, so that GetCACert
	// returns the CA certificate followed by the RA certificate.
	RA bool

	// NextCA announces a second issuing CA certificate through GetNextCACert.
	NextCA bool

	// BusyInterval answers HTTP 503 without Retry-After to a PKIOperation that arrives within this
	// time of the previous one, as some CAs do. Zero never answers 503.
	BusyInterval time.Duration
}

// identity is a certificate and its RSA key.
type identity struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// pending is an enrollment that waits for the CA to decide.
type pending struct {
	csr *x509.CertificateRequest
	// polls counts down the CertPoll messages to the one that issues the certificate.
	polls int
	// issued is set once the certificate is issued, so that a repeated poll returns it again.
	issued *x509.Certificate
}

// CA is a SCEP test CA with an RSA root, an RSA issuing CA and optionally an RA and a next issuing
// CA. The root signs the issuing CAs, and the issuing CA signs every certificate and CRL.
type CA struct {
	opts      Options
	root      identity
	issuing   identity
	ra        *identity
	next      *identity
	responder *scepserver.Responder

	mu sync.Mutex
	// issued holds every issued certificate by its serial number, for GetCert.
	issued map[string]*x509.Certificate
	// pending holds the enrollments by transaction ID.
	pending map[scep.TransactionID]*pending
	// last is when the last PKIOperation reached the CA, for BusyInterval.
	last time.Time
}

// New creates a CA with new keys.
func New(opts Options) (*CA, error) {
	if opts.PendingPolls < 0 {
		return nil, errors.New("scepca: PendingPolls must not be negative")
	}
	if opts.BusyInterval < 0 {
		return nil, errors.New("scepca: BusyInterval must not be negative")
	}
	ca := &CA{opts: opts, issued: map[string]*x509.Certificate{}, pending: map[scep.TransactionID]*pending{}}
	var err error
	rootTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "certrally SCEP Mock Root CA"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ca.root, err = newIdentity(rootTmpl, nil, 20*validity); err != nil {
		return nil, err
	}
	if ca.issuing, err = newIdentity(issuingTemplate("certrally SCEP Mock CA"), &ca.root, 10*validity); err != nil {
		return nil, err
	}
	ca.responder = &scepserver.Responder{SignerCertificate: ca.issuing.cert, SignerKey: ca.issuing.key}
	if opts.RA {
		raTmpl := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "certrally SCEP Mock RA"},
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		ra, err := newIdentity(raTmpl, &ca.issuing, validity)
		if err != nil {
			return nil, err
		}
		ca.ra = &ra
		ca.responder = &scepserver.Responder{
			SignerCertificate: ra.cert,
			SignerKey:         ra.key,
			Certificates:      []*x509.Certificate{ca.issuing.cert},
		}
	}
	if opts.NextCA {
		next, err := newIdentity(issuingTemplate("certrally SCEP Mock Next CA"), &ca.root, 10*validity)
		if err != nil {
			return nil, err
		}
		ca.next = &next
	}
	return ca, nil
}

// issuingTemplate returns the template of an issuing CA certificate named cn.
func issuingTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: cn},
		// The issuing CA decrypts requests and signs answers when no RA does.
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
}

// newIdentity creates an RSA-2048 key and a certificate for it from tmpl, signed by parent or
// self-signed when parent is nil.
func newIdentity(tmpl *x509.Certificate, parent *identity, lifetime time.Duration) (identity, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return identity{}, err
	}
	if tmpl.SerialNumber, err = newSerial(); err != nil {
		return identity{}, err
	}
	now := time.Now()
	tmpl.NotBefore, tmpl.NotAfter = now.Add(-time.Minute), now.Add(lifetime)
	issuerCert, issuerKey := tmpl, key
	if parent != nil {
		issuerCert, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, key.Public(), issuerKey)
	if err != nil {
		return identity{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return identity{}, err
	}
	return identity{cert: cert, key: key}, nil
}

// Handler returns the SCEP HTTP handler of the CA. It answers GetNextCACert only when the CA has a
// next issuing CA.
func (ca *CA) Handler(opts scepserver.Options) (*scepserver.Handler, error) {
	if ca.next != nil {
		return scepserver.NewHandler(&rollover{ca}, opts)
	}
	return scepserver.NewHandler(ca, opts)
}

// Root returns the root CA certificate, which clients trust.
func (ca *CA) Root() *x509.Certificate { return ca.root.cert }

// Certificate returns the issuing CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.issuing.cert }

// CACertificates answers GetCACert with the issuing CA certificate, followed by the RA certificate
// when there is one.
func (ca *CA) CACertificates(_ context.Context, name string) ([]*x509.Certificate, error) {
	if !ca.serves(name) {
		return nil, scepserver.ErrNotFound
	}
	certs := []*x509.Certificate{ca.issuing.cert}
	if ca.ra != nil {
		certs = append(certs, ca.ra.cert)
	}
	return certs, nil
}

// CACertificateChain answers GetCACertChain with the issuing CA and the root.
func (ca *CA) CACertificateChain(_ context.Context, name string) ([]*x509.Certificate, error) {
	if !ca.serves(name) {
		return nil, scepserver.ErrNotFound
	}
	return []*x509.Certificate{ca.issuing.cert, ca.root.cert}, nil
}

// serves reports whether name is the CA name, or whether the CA accepts any name.
func (ca *CA) serves(name string) bool {
	return ca.opts.Name == "" || name == ca.opts.Name
}

// Responder returns the identity that decrypts requests encrypted for recipient.
func (ca *CA) Responder(_ context.Context, recipient scep.IssuerAndSerial) (*scepserver.Responder, error) {
	cert := ca.responder.SignerCertificate
	if !bytes.Equal(recipient.Issuer, cert.RawIssuer) || recipient.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return nil, scepserver.ErrNotFound
	}
	return ca.responder, nil
}

// Enroll answers a PKCSReq, RenewalReq or UpdateReq. A PKCSReq must carry the challenge password
// and a renewal must be signed with a valid certificate of the CA. A request with the transaction
// ID of a pending one is answered as a poll.
func (ca *CA) Enroll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	msg := req.Message
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if err := ca.busy(); err != nil {
		return nil, err
	}
	if p, ok := ca.pending[msg.TransactionID]; ok {
		return ca.poll(p)
	}
	switch msg.MessageType {
	case scep.PKCSReq:
		if ca.opts.Challenge != nil &&
			subtle.ConstantTimeCompare([]byte(msg.ChallengePassword), ca.opts.Challenge) != 1 {
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: errors.New("wrong challenge password")}
		}
	default:
		if err := ca.verify(msg.SignerCertificate); err != nil {
			return nil, &scepserver.Failure{Info: scep.BadRequest, Err: fmt.Errorf("renewal signer: %w", err)}
		}
	}
	p := &pending{csr: msg.CSR, polls: ca.opts.PendingPolls}
	if p.polls > 0 {
		ca.pending[msg.TransactionID] = p
		return nil, scepserver.ErrPending
	}
	return ca.issue(p)
}

// Poll answers a CertPoll for a pending enrollment.
func (ca *CA) Poll(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if err := ca.busy(); err != nil {
		return nil, err
	}
	p, ok := ca.pending[req.Message.TransactionID]
	if !ok {
		return nil, &scepserver.Failure{Info: scep.BadCertID, Err: errors.New("no pending request has this transaction ID")}
	}
	return ca.poll(p)
}

// poll counts the CertPoll messages for p and issues its certificate at the PendingPolls-th one.
// The caller holds ca.mu.
func (ca *CA) poll(p *pending) ([]*x509.Certificate, error) {
	if p.issued != nil {
		return []*x509.Certificate{p.issued}, nil
	}
	if p.polls--; p.polls > 0 {
		return nil, scepserver.ErrPending
	}
	return ca.issue(p)
}

// GetCert returns a certificate the CA issued.
func (ca *CA) GetCert(_ context.Context, req *scepserver.Request) ([]*x509.Certificate, error) {
	id := req.Message.CertificateID
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if err := ca.busy(); err != nil {
		return nil, err
	}
	cert, ok := ca.issued[id.SerialNumber.String()]
	if !ok || !bytes.Equal(id.Issuer, ca.issuing.cert.RawSubject) {
		return nil, &scepserver.Failure{
			Info: scep.BadCertID,
			Err:  errors.New("the CA issued no certificate with this issuer and serial number"),
		}
	}
	return []*x509.Certificate{cert}, nil
}

// GetCRL returns a new, empty CRL of the issuing CA.
func (ca *CA) GetCRL(_ context.Context, req *scepserver.Request) ([]byte, error) {
	ca.mu.Lock()
	err := ca.busy()
	ca.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(req.Message.CertificateID.Issuer, ca.issuing.cert.RawSubject) {
		return nil, &scepserver.Failure{Info: scep.BadCertID, Err: errors.New("the CA does not issue for this issuer")}
	}
	now := time.Now()
	return x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(24 * time.Hour),
	}, ca.issuing.cert, ca.issuing.key)
}

// busy returns a *scepserver.Busy without Retry-After when the previous PKIOperation arrived within
// BusyInterval, and otherwise records the time of this one. The caller holds ca.mu.
func (ca *CA) busy() error {
	now := time.Now()
	if ca.opts.BusyInterval > 0 && now.Sub(ca.last) < ca.opts.BusyInterval {
		return &scepserver.Busy{}
	}
	ca.last = now
	return nil
}

// verify reports whether cert was issued by the issuing CA and is valid now.
func (ca *CA) verify(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("no signer certificate")
	}
	if err := cert.CheckSignatureFrom(ca.issuing.cert); err != nil {
		return errors.New("the certificate was not issued by this CA")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("the certificate is not valid now")
	}
	return nil
}

// issue certifies the key of p with the subject and subjectAltName of its request. The caller holds
// ca.mu.
func (ca *CA) issue(p *pending) ([]*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		RawSubject:   p.csr.RawSubject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	// An RSA key signs RenewalReq and GetCert requests and decrypts their answers.
	if _, ok := p.csr.PublicKey.(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, ext := range p.csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.issuing.cert, p.csr.PublicKey, ca.issuing.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	p.issued = cert
	ca.issued[cert.SerialNumber.String()] = cert
	return []*x509.Certificate{cert}, nil
}

// rollover is a CA that announces its next issuing CA certificate.
type rollover struct {
	*CA
}

// NextCACertificates answers GetNextCACert with the next issuing CA certificate.
func (r *rollover) NextCACertificates(_ context.Context, name string) ([]*x509.Certificate, *scepserver.Responder, error) {
	if !r.serves(name) {
		return nil, nil, scepserver.ErrNotFound
	}
	return []*x509.Certificate{r.next.cert}, r.responder, nil
}

// newSerial returns a random positive serial number of 128 bits.
func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
