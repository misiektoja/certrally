package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/pemfile"
)

// oidClientTest is a private key purpose that the template tests request by OID.
var oidClientTest = asn1.ObjectIdentifier{1, 2, 3, 4}

// newTemplateCert makes a self-signed certificate from tmpl and writes it to a PEM file.
func newTemplateCert(t *testing.T, tmpl *x509.Certificate) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(1)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "template.pem")
	if err := os.WriteFile(path, pemfile.EncodeCertificates([]*x509.Certificate{cert}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, path
}

// findExtension returns the extension with the identifier id, or nil.
func findExtension(extensions []pkix.Extension, id asn1.ObjectIdentifier) *pkix.Extension {
	i := slices.IndexFunc(extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(id) })
	if i < 0 {
		return nil
	}
	return &extensions[i]
}

// requestTemplate returns the subject and extensions that the first request of capture asks for,
// from the certificate template of an ir or cr or from the PKCS#10 request of a p10cr.
func requestTemplate(t *testing.T, capture string) (rawSubject []byte, extensions []pkix.Extension) {
	t.Helper()
	msg := firstMessage(t, capture)
	if msg.Body.Type == pkicmp.BodyTypeP10CR {
		csr, err := msg.Body.P10CR()
		if err != nil {
			t.Fatal(err)
		}
		return csr.RawSubject, csr.Extensions
	}
	tmpl := certReqMsg(t, msg).CertReq.CertTemplate
	if len(tmpl.Extensions) > 0 {
		if _, err := asn1.Unmarshal(tmpl.Extensions, &extensions); err != nil {
			t.Fatal(err)
		}
	}
	return tmpl.RawSubject, extensions
}

// sameExtension reports whether got and want are both absent or carry the same value and criticality.
func sameExtension(got, want *pkix.Extension) bool {
	if got == nil || want == nil {
		return got == want
	}
	return got.Critical == want.Critical && bytes.Equal(got.Value, want.Value)
}

// TestKeyUsageExtension checks that --key-usage encodes each bit as crypto/x509 does, in the RFC 5280
// bit order and without trailing zero bits.
func TestKeyUsageExtension(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// x509Encoding returns the keyUsage that crypto/x509 writes into a certificate for usage.
	x509Encoding := func(usage x509.KeyUsage) []byte {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), KeyUsage: usage}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return findExtension(cert.Extensions, oidKeyUsage).Value
	}
	for bit, name := range keyUsageNames {
		ext, err := keyUsageExtension([]string{strings.ToUpper(name)})
		if err != nil {
			t.Fatal(err)
		}
		if want := x509Encoding(x509.KeyUsage(1) << bit); !bytes.Equal(ext.Value, want) || !ext.Critical {
			t.Errorf("%s: keyUsage %x, critical %v, want %x and critical", name, ext.Value, ext.Critical, want)
		}
	}
	all, err := keyUsageExtension(slices.Concat(keyUsageNames, []string{contentCommitment}))
	if err != nil {
		t.Fatal(err)
	}
	if want := x509Encoding(1<<len(keyUsageNames) - 1); !bytes.Equal(all.Value, want) {
		t.Errorf("all usages: keyUsage %x, want %x", all.Value, want)
	}

	tests := []struct {
		names []string
		want  []byte
	}{
		{[]string{"digitalSignature", "keyEncipherment"}, []byte{0x03, 0x02, 0x05, 0xa0}},
		{[]string{"keyCertSign", "cRLSign", "keyCertSign"}, []byte{0x03, 0x02, 0x01, 0x06}},
		{[]string{contentCommitment}, []byte{0x03, 0x02, 0x06, 0x40}},
		{[]string{"keyAgreement", "decipherOnly"}, []byte{0x03, 0x03, 0x07, 0x08, 0x80}},
	}
	for _, tt := range tests {
		ext, err := keyUsageExtension(tt.names)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ext.Value, tt.want) {
			t.Errorf("%v: keyUsage %x, want %x", tt.names, ext.Value, tt.want)
		}
	}
}

// TestExtKeyUsageExtension checks that the --ext-key-usage names stand for the key purposes that
// crypto/x509 knows by those names, that cmcRA stands for id-kp-cmcRA and that a dotted OID passes
// through.
func TestExtKeyUsageExtension(t *testing.T) {
	ext, err := extKeyUsageExtension(slices.Concat(keyPurposeNames, []string{"SERVERAUTH", "1.2.3.4"}))
	if err != nil {
		t.Fatal(err)
	}
	if ext.Critical || !ext.Id.Equal(oidExtKeyUsage) {
		t.Errorf("extendedKeyUsage is %v, critical %v", ext.Id, ext.Critical)
	}
	cert, _ := newTemplateCert(t, &x509.Certificate{ExtraExtensions: []pkix.Extension{ext}})
	want := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageOCSPSigning,
		x509.ExtKeyUsageAny,
	}
	if !slices.Equal(cert.ExtKeyUsage, want) {
		t.Errorf("key purposes %v, want %v", cert.ExtKeyUsage, want)
	}
	wantOther := []asn1.ObjectIdentifier{oidKeyPurposeCMCRA, oidClientTest}
	if !slices.EqualFunc(cert.UnknownExtKeyUsage, wantOther, asn1.ObjectIdentifier.Equal) {
		t.Errorf("other key purposes %v, want %v", cert.UnknownExtKeyUsage, wantOther)
	}
}

// TestEnrollTemplateExtensions checks the request that --key-usage, --ext-key-usage and
// --template-cert send to certrally mock. The mock CA issues extendedKeyUsage as requested but sets
// keyUsage itself, so the keyUsage checks look at the request.
func TestEnrollTemplateExtensions(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	usages := []string{"--key-usage", "digitalSignature,keyEncipherment", "--ext-key-usage", "serverAuth",
		"--ext-key-usage", "clientAuth"}
	wantKU := &pkix.Extension{Critical: true, Value: []byte{0x03, 0x02, 0x05, 0xa0}}
	wantEKU := &pkix.Extension{Value: []byte{0x30, 0x14,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}}

	// enroll runs enroll against the mock CA and returns the capture file and the issued certificate.
	enroll := func(t *testing.T, args ...string) (string, *x509.Certificate) {
		t.Helper()
		code, errOut, capture := mockEnroll(t, m, args...)
		if code != exitOK {
			t.Fatalf("enroll exited with %d:\n%s", code, errOut)
		}
		return capture, readCert(t, filepath.Join(filepath.Dir(capture), "cert.pem"))
	}
	// check compares the subject and extensions of the request in capture with the wanted ones.
	check := func(t *testing.T, capture string, subject []byte, san, ku, eku *pkix.Extension) {
		t.Helper()
		rawSubject, extensions := requestTemplate(t, capture)
		if !bytes.Equal(rawSubject, subject) {
			t.Errorf("subject %x, want %x", rawSubject, subject)
		}
		for _, w := range []struct {
			name string
			id   asn1.ObjectIdentifier
			want *pkix.Extension
		}{{"subjectAltName", oidSubjectAltName, san}, {"keyUsage", oidKeyUsage, ku}, {"extendedKeyUsage", oidExtKeyUsage, eku}} {
			if got := findExtension(extensions, w.id); !sameExtension(got, w.want) {
				t.Errorf("%s = %+v, want %+v", w.name, got, w.want)
			}
		}
	}
	refSubject, err := asn1.Marshal(pkix.Name{CommonName: testRef}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flags", func(t *testing.T) {
		capture, cert := enroll(t, usages...)
		check(t, capture, refSubject, nil, wantKU, wantEKU)
		if want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}; !slices.Equal(cert.ExtKeyUsage, want) {
			t.Errorf("the issued certificate has key purposes %v, want %v", cert.ExtKeyUsage, want)
		}

		// A template copied from the issued certificate asks for what the CA issued.
		again, _ := enroll(t, "--template-cert", filepath.Join(filepath.Dir(capture), "cert.pem"))
		check(t, again, cert.RawSubject, nil,
			findExtension(cert.Extensions, oidKeyUsage), findExtension(cert.Extensions, oidExtKeyUsage))
	})

	t.Run("p10cr", func(t *testing.T) {
		capture, _ := enroll(t, append([]string{"--type", "p10cr"}, usages...)...)
		check(t, capture, refSubject, nil, wantKU, wantEKU)
	})

	t.Run("kur", func(t *testing.T) {
		capture, cert := enroll(t)
		dir := t.TempDir()
		kurCapture := filepath.Join(dir, "capture.jsonl")
		code, _, errOut := run(t, append([]string{"enroll", "--server", m.url, "--type", "kur",
			"--cert", filepath.Join(filepath.Dir(capture), "cert.pem"), "--key", filepath.Join(filepath.Dir(capture), "key.pem"),
			"--capture", kurCapture, "--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem")},
			usages...)...)
		if code != exitOK {
			t.Fatalf("kur exited with %d:\n%s", code, errOut)
		}
		check(t, kurCapture, cert.RawSubject, nil, wantKU, wantEKU)
	})

	tmpl, tmplFile := newTemplateCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "device-42", Organization: []string{"Example"}},
		DNSNames:              []string{"device-42.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidClientTest},
		BasicConstraintsValid: true,
	})
	tmplSAN := findExtension(tmpl.Extensions, oidSubjectAltName)
	tmplKU := findExtension(tmpl.Extensions, oidKeyUsage)
	tmplEKU := findExtension(tmpl.Extensions, oidExtKeyUsage)

	t.Run("template-cert", func(t *testing.T) {
		for _, reqType := range []string{typeIR, typeP10CR} {
			capture, _ := enroll(t, "--type", reqType, "--template-cert", tmplFile)
			check(t, capture, tmpl.RawSubject, tmplSAN, tmplKU, tmplEKU)
			if _, extensions := requestTemplate(t, capture); len(extensions) != 3 {
				t.Errorf("%s: the request asks for %d extensions, want subjectAltName, keyUsage and extendedKeyUsage", reqType, len(extensions))
			}
		}
	})

	t.Run("overrides", func(t *testing.T) {
		capture, _ := enroll(t, "--template-cert", tmplFile, "--subject", "CN=other", "--san", "dns:other.example.com",
			"--key-usage", "keyCertSign")
		subject, err := asn1.Marshal(pkix.Name{CommonName: "other"}.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		san := &pkix.Extension{Value: []byte{0x30, 0x13, 0x82, 0x11}}
		san.Value = append(san.Value, "other.example.com"...)
		check(t, capture, subject, san, &pkix.Extension{Critical: true, Value: []byte{0x03, 0x02, 0x02, 0x04}}, tmplEKU)

		capture, _ = enroll(t, "--template-cert", tmplFile, "--ext-key-usage", "timeStamping")
		eku := &pkix.Extension{Value: []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08}}
		check(t, capture, tmpl.RawSubject, tmplSAN, tmplKU, eku)
	})

	t.Run("empty subject", func(t *testing.T) {
		// A certificate named only in subjectAltName gives a request with a NULL-DN subject and a
		// critical subjectAltName, as RFC 5280 §4.2.1.6 requires.
		bare, bareFile := newTemplateCert(t, &x509.Certificate{
			ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: tmplSAN.Value}},
		})
		capture, _ := enroll(t, "--template-cert", bareFile)
		check(t, capture, []byte{0x30, 0x00}, findExtension(bare.Extensions, oidSubjectAltName), nil, nil)

		// With --subject the copied subjectAltName need not be critical.
		capture, _ = enroll(t, "--template-cert", bareFile, "--subject", "CN=named")
		_, extensions := requestTemplate(t, capture)
		if san := findExtension(extensions, oidSubjectAltName); san == nil || san.Critical || !bytes.Equal(san.Value, tmplSAN.Value) {
			t.Errorf("subjectAltName = %+v, want the copied value, not critical", san)
		}
	})
}

// TestEnrollTemplateUsage checks the usage errors of --key-usage, --ext-key-usage and --template-cert.
func TestEnrollTemplateUsage(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca)
	sent := ca.requests.Load()
	multiRDN, err := asn1.Marshal(pkix.RDNSequence{{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "device-42"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, multiFile := newTemplateCert(t, &x509.Certificate{RawSubject: multiRDN})
	dir := t.TempDir()
	outputs := []string{"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem")}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"key-usage name", []string{"--key-usage", "digitalSignature,sign"}, `invalid --key-usage "sign"`},
		{"key-usage empty", []string{"--key-usage", ""}, "holds an empty name"},
		{"key-usage empty item", []string{"--key-usage", "digitalSignature,"}, "holds an empty name"},
		{"ext-key-usage name", []string{"--ext-key-usage", "webServer"}, `invalid --ext-key-usage "webServer"`},
		{"ext-key-usage OID", []string{"--ext-key-usage", "1.2.x"}, `invalid OID "1.2.x"`},
		{"key-usage with csr", []string{"--type", "p10cr", "--csr", "request.csr", "--key-usage", "digitalSignature"}, "cannot change a request given with --csr"},
		{"template-cert with csr", []string{"--type", "p10cr", "--csr", "request.csr", "--template-cert", certFile}, "cannot change a request given with --csr"},
		{"template-cert missing", []string{"--template-cert", filepath.Join(dir, "missing.pem")}, "missing.pem"},
		{"template-cert multi-valued RDN", []string{"--template-cert", multiFile}, "multi-valued RDN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"enroll", "--server", ca.url, "--ref", testRef}, append(tt.args, outputs...)...)
			code, _, errOut := run(t, args...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want 1 and %q in:\n%s", code, tt.want, errOut)
			}
		})
	}
	t.Run("template-cert with kur", func(t *testing.T) {
		code, _, errOut := run(t, append([]string{"enroll", "--server", ca.url, "--type", "kur", "--cert", certFile,
			"--key", keyFile, "--template-cert", certFile}, outputs...)...)
		if want := "--template-cert needs --type ir, cr or p10cr"; code != exitLocal || !errorContains(errOut, want) {
			t.Errorf("exited with %d, want 1 and %q in:\n%s", code, want, errOut)
		}
	})
	if n := ca.requests.Load(); n != sent {
		t.Errorf("the CA received %d requests", n-sent)
	}

	// --subject replaces the subject that cannot be copied.
	enrollIR(t, ca, "--template-cert", multiFile, "--subject", "CN=device-42")
}

// TestTemplateCompletion checks that completion of a comma-separated list offers the names not yet
// typed, after the items already typed.
func TestTemplateCompletion(t *testing.T) {
	_, out, _ := run(t, "__complete", "enroll", "--key-usage", "digitalSignature,KEYENCIPHERMENT,")
	lines := strings.Split(out, "\n")
	if !slices.Contains(lines, "digitalSignature,KEYENCIPHERMENT,cRLSign") {
		t.Errorf("completion lacks cRLSign after the typed items:\n%s", out)
	}
	if slices.ContainsFunc(lines, func(s string) bool { return strings.HasSuffix(s, ",keyEncipherment") }) {
		t.Errorf("completion offers keyEncipherment again:\n%s", out)
	}
	_, out, _ = run(t, "__complete", "enroll", "--ext-key-usage", "")
	if !slices.Contains(strings.Split(out, "\n"), "ocspSigning") {
		t.Errorf("completion lacks ocspSigning:\n%s", out)
	}
}
