package profile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// oidECDSAWithSHA256 marks a test message as signed. The checks never verify the signature.
var oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

// testCA is the name of the CA in the test responses.
var testCA = pkix.Name{CommonName: "Test CA"}

// newCertificate returns a certificate with a subject key identifier and its key. It is self-signed
// unless issuer and issuerKey are given.
func newCertificate(t *testing.T, subject pkix.Name, issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := make([]byte, 8)
	_, _ = rand.Read(keyID)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		SubjectKeyId:          keyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if issuer == nil {
		issuer, issuerKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// issuing returns an ip that issues cert, with the given extraCerts and caPubs.
func issuing(cert *x509.Certificate, extraCerts, caPubs []*x509.Certificate) *pkicmp.PKIMessage {
	rep := &pkicmp.CertRepMessage{Response: []pkicmp.CertResponse{{
		Status: pkicmp.PKIStatusInfo{Status: pkicmp.StatusAccepted},
		CertifiedKeyPair: &pkicmp.CertifiedKeyPair{CertOrEncCert: pkicmp.CertOrEncCert{
			Certificate: &pkicmp.CMPCertificate{Raw: cert.Raw},
		}},
	}}}
	for _, c := range caPubs {
		rep.CAPubs = append(rep.CAPubs, pkicmp.CMPCertificate{Raw: c.Raw})
	}
	m := message(pkicmp.NewIPBody(rep), testCA, oidPBMAC1)
	for _, c := range extraCerts {
		m.ExtraCerts = append(m.ExtraCerts, pkicmp.CMPCertificate{Raw: c.Raw})
	}
	return m
}

// message returns a message from the named sender protected with alg, or unprotected when alg is nil.
func message(body *pkicmp.PKIBody, sender pkix.Name, alg asn1.ObjectIdentifier) *pkicmp.PKIMessage {
	m := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(sender)})
	if alg != nil {
		m.Header.ProtectionAlg = &pkicmp.AlgorithmIdentifier{Algorithm: alg}
	}
	return m
}

// signedBy marks m as signed with cert, the way a conforming CA does.
func signedBy(m *pkicmp.PKIMessage, cert *x509.Certificate) *pkicmp.PKIMessage {
	m.Header.ProtectionAlg = &pkicmp.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
	m.Header.SenderKID = cert.SubjectKeyId
	m.ExtraCerts = []pkicmp.CMPCertificate{{Raw: cert.Raw}}
	return m
}

// info returns a generalInfo item with a NULL value.
func info(oid asn1.ObjectIdentifier) pkicmp.InfoTypeAndValue {
	return pkicmp.InfoTypeAndValue{InfoType: oid, InfoValue: []byte{0x05, 0x00}}
}

// TestCheck checks each rule with a response that breaks it and one that does not.
func TestCheck(t *testing.T) {
	ca, caKey := newCertificate(t, testCA, nil, nil)
	other, _ := newCertificate(t, pkix.Name{CommonName: "Other"}, nil, nil)
	device, _ := newCertificate(t, pkix.Name{CommonName: "device"}, ca, caKey)

	macIR := func() *pkicmp.PKIMessage {
		return message(pkicmp.NewIRBody(&pkicmp.CertReqMessages{}), pkix.Name{CommonName: "device"}, oidPBMAC1)
	}
	signedIR := func() *pkicmp.PKIMessage { return signedBy(macIR(), device) }
	certConf := func() *pkicmp.PKIMessage {
		return message(pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{}), pkix.Name{CommonName: "device"}, oidPBMAC1)
	}
	genm := func() *pkicmp.PKIMessage {
		return signedBy(message(pkicmp.NewGenMBody(), pkix.Name{CommonName: "device"}, nil), device)
	}
	// ip returns a MAC-protected ip that issues device with the CA certificate in extraCerts.
	ip := func() *pkicmp.PKIMessage { return issuing(device, []*x509.Certificate{ca}, nil) }
	genp := func() *pkicmp.PKIMessage { return signedBy(message(pkicmp.NewGenPBody(), testCA, nil), ca) }
	errorMsg := func(status pkicmp.PKIStatus) *pkicmp.PKIMessage {
		body := pkicmp.NewErrorBody(&pkicmp.ErrorMsgContent{PKIStatusInfo: pkicmp.PKIStatusInfo{Status: status}})
		return signedBy(message(body, testCA, nil), ca)
	}
	pkiconf := func(raw []byte) *pkicmp.PKIMessage {
		return message(&pkicmp.PKIBody{Type: pkicmp.BodyTypePKIConf, Raw: raw}, testCA, oidPBMAC1)
	}
	with := func(m *pkicmp.PKIMessage, change func(*pkicmp.PKIMessage)) *pkicmp.PKIMessage {
		change(m)
		return m
	}

	tests := []struct {
		name      string
		req, resp *pkicmp.PKIMessage
		// want is a fragment of the only finding, or "" for none.
		want string
	}{
		{"conforming ip", macIR(), ip(), ""},
		{"pvno", macIR(), with(ip(), func(m *pkicmp.PKIMessage) { m.Header.PVNO = 1 }), "The ip response has pvno 1 instead of 2 or 3"},
		{"no senderNonce", macIR(), with(ip(), func(m *pkicmp.PKIMessage) { m.Header.SenderNonce = nil }), "has no senderNonce"},
		{"short senderNonce", macIR(), with(ip(), func(m *pkicmp.PKIMessage) { m.Header.SenderNonce = make([]byte, 8) }),
			"has a senderNonce of 64 bits instead of at least 128"},
		{"unrequested implicitConfirm", macIR(), with(ip(), func(m *pkicmp.PKIMessage) {
			m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidImplicitConfirm)}
		}), "grants implicitConfirm, which the request did not ask for"},
		{"requested implicitConfirm",
			with(macIR(), func(m *pkicmp.PKIMessage) { m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidImplicitConfirm)} }),
			with(ip(), func(m *pkicmp.PKIMessage) { m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidImplicitConfirm)} }), ""},
		{"implicitConfirm in genp", genm(), with(genp(), func(m *pkicmp.PKIMessage) {
			m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidImplicitConfirm)}
		}), "only ip, cp and kup responses may carry"},
		{"implicitConfirm and confirmWaitTime",
			with(macIR(), func(m *pkicmp.PKIMessage) { m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidImplicitConfirm)} }),
			with(ip(), func(m *pkicmp.PKIMessage) {
				m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidImplicitConfirm), info(oidConfirmWaitTime)}
			}), "carries both implicitConfirm and confirmWaitTime"},
		{"confirmWaitTime without messageTime", macIR(), with(ip(), func(m *pkicmp.PKIMessage) {
			m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{info(oidConfirmWaitTime)}
			m.Header.MessageTime = time.Time{}
		}), "carries confirmWaitTime without messageTime"},
		{"certProfile", genm(), with(genp(), func(m *pkicmp.PKIMessage) {
			m.Header.GeneralInfo = []pkicmp.InfoTypeAndValue{pkicmp.NewCertProfileInfo("tls")}
		}), "carries certProfile, which only requests may carry"},
		{"signed answer to MAC", macIR(), signedBy(ip(), ca), "is signed, but the request is MAC-protected"},
		{"MAC answer to signature", signedIR(), ip(), "is MAC-protected, but the request is signed"},
		{"signed error to MAC", macIR(), errorMsg(pkicmp.StatusRejection), ""},
		{"no senderKID", genm(), with(genp(), func(m *pkicmp.PKIMessage) { m.Header.SenderKID = nil }),
			"has no senderKID, although its protection certificate has a subject key identifier"},
		{"no protection certificate", genm(), with(genp(), func(m *pkicmp.PKIMessage) { m.ExtraCerts = nil }),
			"carries no extraCerts, so its protection certificate is missing"},
		{"protection certificate not first", genm(), with(genp(), func(m *pkicmp.PKIMessage) {
			m.ExtraCerts = []pkicmp.CMPCertificate{{Raw: other.Raw}, {Raw: ca.Raw}}
		}), "does not start extraCerts with its protection certificate"},
		{"no chain", macIR(), with(ip(), func(m *pkicmp.PKIMessage) { m.ExtraCerts = nil }),
			"carries no extraCerts, so the chain of the new certificate is missing"},
		{"later message without extraCerts", signedBy(certConf(), device), with(signedBy(pkiconf([]byte{0xb3, 0x02, 0x05, 0x00}), ca),
			func(m *pkicmp.PKIMessage) { m.ExtraCerts = nil }), ""},
		{"error status", genm(), errorMsg(pkicmp.StatusAccepted), "The error response has status accepted instead of rejection"},
		{"waiting error", genm(), errorMsg(pkicmp.StatusWaiting), ""},
		{"empty pkiconf", certConf(), pkiconf([]byte{0xb3, 0x00}), "The pkiconf response is empty instead of holding NULL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Check(tt.req, tt.resp, nil)
			switch {
			case tt.want == "" && len(findings) != 0:
				t.Errorf("findings = %v, want none", findings)
			case tt.want != "" && (len(findings) != 1 || !strings.Contains(findings[0].Text, tt.want)):
				t.Errorf("findings = %v, want one with %q", findings, tt.want)
			}
		})
	}
}

// TestCheckChain checks when a new certificate needs its chain in extraCerts. Self-signed
// certificates are left out, so a certificate issued by a known root needs none.
func TestCheckChain(t *testing.T) {
	const missing = "carries no extraCerts, so the chain of the new certificate is missing"
	root, rootKey := newCertificate(t, testCA, nil, nil)
	sub, subKey := newCertificate(t, pkix.Name{CommonName: "Issuing CA"}, root, rootKey)
	fromRoot, _ := newCertificate(t, pkix.Name{CommonName: "device"}, root, rootKey)
	fromSub, _ := newCertificate(t, pkix.Name{CommonName: "device"}, sub, subKey)
	other, _ := newCertificate(t, pkix.Name{CommonName: "Test CA"}, nil, nil)
	req := message(pkicmp.NewIRBody(&pkicmp.CertReqMessages{}), pkix.Name{CommonName: "device"}, oidPBMAC1)
	certs := func(c ...*x509.Certificate) []*x509.Certificate { return c }

	tests := []struct {
		name    string
		resp    *pkicmp.PKIMessage
		trusted []*x509.Certificate
		want    string
	}{
		{"root in caPubs", issuing(fromRoot, nil, certs(root)), nil, ""},
		{"trusted root", issuing(fromRoot, nil, nil), certs(root), ""},
		{"unknown root", issuing(fromRoot, nil, nil), nil, missing},
		{"root with another key", issuing(fromRoot, nil, certs(other)), nil, missing},
		{"trusted intermediate", issuing(fromSub, nil, certs(root)), certs(root, sub), missing},
		{"intermediate in extraCerts", issuing(fromSub, certs(sub), certs(root)), nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Check(req, tt.resp, tt.trusted)
			switch {
			case tt.want == "" && len(findings) != 0:
				t.Errorf("findings = %v, want none", findings)
			case tt.want != "" && (len(findings) != 1 || !strings.Contains(findings[0].Text, tt.want)):
				t.Errorf("findings = %v, want one with %q", findings, tt.want)
			}
		})
	}
}

// TestFindingString checks that a finding reads as one sentence that names its rule.
func TestFindingString(t *testing.T) {
	f := Finding{Text: "The ip response has no senderNonce", Rule: "RFC 9483 section 3.5"}
	if got, want := f.String(), "The ip response has no senderNonce (RFC 9483 section 3.5)."; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
