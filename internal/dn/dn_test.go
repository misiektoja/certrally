package dn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// TestParseName checks encoding order, escapes, quotes and OIDs.
func TestParseName(t *testing.T) {
	tests := []struct {
		in   string
		want string // pkix.Name.String of the result
	}{
		{"CN=device-42,O=Example,C=PL", "CN=device-42,O=Example,C=PL"},
		{"cn=a, o=b", "CN=a,O=b"},
		{`CN=a\,b`, `CN=a\,b`},
		{`CN=a\2Cb`, `CN=a\,b`},
		{`CN="a,b"`, `CN=a\,b`},
		{`CN=\ padded\ `, `CN=\ padded\ `},
		{"CN=  trimmed  ", "CN=trimmed"},
		{"CN=Zo\\C3\\AB", "CN=Zoë"},
		{"2.5.4.3=by-oid", "CN=by-oid"},
		{"UID=u1,FOO=x", ""},
		{"DC=zoë", ""},
	}
	for _, tt := range tests {
		name, err := ParseName(tt.in)
		if tt.want == "" {
			if err == nil {
				t.Errorf("ParseName(%q) succeeded, want an error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseName(%q): %v", tt.in, err)
			continue
		}
		if got := name.String(); got != tt.want {
			t.Errorf("ParseName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestParseNameDomainComponent checks that a domainComponent is encoded as an IA5String, as RFC 4519
// section 2.4 requires, and shown by its keyword.
func TestParseNameDomainComponent(t *testing.T) {
	name, err := ParseName("CN=host,DC=example,DC=org")
	if err != nil {
		t.Fatal(err)
	}
	rdns := name.ToRDNSequence()
	for _, rdn := range rdns[:2] {
		der, err := asn1.Marshal(rdn[0].Value)
		if err != nil || len(der) == 0 || der[0] != asn1.TagIA5String {
			t.Errorf("domainComponent %v encodes as % x, want an IA5String", rdn[0].Value, der)
		}
	}
	if got := String(rdns); got != "CN=host,DC=example,DC=org" {
		t.Errorf("String = %q", got)
	}
}

// TestParseNameOrder checks that the most specific RDN, written first, is encoded last.
func TestParseNameOrder(t *testing.T) {
	name, err := ParseName("CN=leaf,OU=unit,O=org,C=PL")
	if err != nil {
		t.Fatal(err)
	}
	rdns := name.ToRDNSequence()
	got := make([]string, 0, len(rdns))
	for _, rdn := range rdns {
		got = append(got, rdn[0].Value.(string))
	}
	if strings.Join(got, "/") != "PL/org/unit/leaf" {
		t.Errorf("encoded order = %v", got)
	}
}

// Attribute types used by the String and Format tests.
var (
	oidCN  = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidO   = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidDC  = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	// oidPseudonym stands for an attribute type that has no keyword.
	oidPseudonym = asn1.ObjectIdentifier{2, 5, 4, 65}
)

// ia5 returns an IA5String value, as a certificate encodes a domainComponent.
func ia5(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(s)}
}

// atv returns an attribute with the given type and value.
func atv(oid asn1.ObjectIdentifier, value any) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: value}
}

// TestParseNameRoundTrip checks that parsing the output of String returns the same encoding.
func TestParseNameRoundTrip(t *testing.T) {
	rdns := pkix.RDNSequence{
		{atv(oidUID, "u-1")},
		{atv(oidCN, ` a+b,"c";<d>\e `)},
		{atv(oidO, "#Zoë\tx")},
		{atv(oidDC, ia5("example"))},
	}
	name, err := ParseName(String(rdns))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := asn1.Marshal(rdns)
	b, _ := asn1.Marshal(name.ToRDNSequence())
	if string(a) != string(b) {
		t.Errorf("round trip of %q gave %q", String(rdns), String(name.ToRDNSequence()))
	}
}

// TestString checks attribute order, keywords, multi-valued RDNs, escapes and values that are not
// strings.
func TestString(t *testing.T) {
	tests := []struct {
		name string
		rdns pkix.RDNSequence
		want string
	}{
		{"empty", nil, ""},
		{"encoded order", pkix.RDNSequence{{atv(oidUID, "u-1")}, {atv(oidCN, "CA")}, {atv(oidO, "Org")}}, "O=Org,CN=CA,UID=u-1"},
		{"multi-valued RDN", pkix.RDNSequence{{atv(oidO, "Org")}, {atv(oidCN, "a"), atv(oidUID, "b")}}, "CN=a+UID=b,O=Org"},
		{"dotted OID", pkix.RDNSequence{{atv(oidPseudonym, "example")}}, "2.5.4.65=example"},
		{"not a string", pkix.RDNSequence{{atv(oidPseudonym, 5)}}, "2.5.4.65=#020105"},
		{"domainComponent", pkix.RDNSequence{{atv(oidDC, "org")}, {atv(oidDC, ia5("example"))}}, "DC=example,DC=org"},
		{"escapes", pkix.RDNSequence{{atv(oidCN, ` a+b,"c";<d>\e `)}}, `CN=\ a\+b\,\"c\"\;\<d\>\\e\ `},
		{"leading hash", pkix.RDNSequence{{atv(oidCN, "#1#")}}, `CN=\#1#`},
		{"control characters", pkix.RDNSequence{{atv(oidCN, "a\nb\x00\x7f")}}, `CN=a\0Ab\00\7F`},
		{"UTF-8", pkix.RDNSequence{{atv(oidCN, "Zoë")}}, "CN=Zoë"},
	}
	for _, tt := range tests {
		if got := String(tt.rdns); got != tt.want {
			t.Errorf("%s: String = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestFormat checks a DER-encoded name and input that is not a name.
func TestFormat(t *testing.T) {
	der, err := asn1.Marshal(pkix.RDNSequence{{atv(oidCN, "CA")}, {atv(oidO, "Org")}})
	if err != nil {
		t.Fatal(err)
	}
	if got := Format(der); got != "O=Org,CN=CA" {
		t.Errorf("Format = %q, want %q", got, "O=Org,CN=CA")
	}
	for _, bad := range [][]byte{nil, {0x30}, append(der, 0)} {
		if got := Format(bad); got != "" {
			t.Errorf("Format(%x) = %q, want \"\"", bad, got)
		}
	}
}

// TestParseNameErrors checks inputs that must be rejected.
func TestParseNameErrors(t *testing.T) {
	for _, in := range []string{
		"", " ", "CN", "=x", "CN=", "XX=1", "1=x", "1.02=x", "CN=a+O=b", "CN=#0403616263",
		`CN="unterminated`, `CN=a\`, "CN=\\FF",
	} {
		if _, err := ParseName(in); err == nil {
			t.Errorf("ParseName(%q) succeeded, want an error", in)
		}
	}
}

// TestSubjectAltName checks each name type, type detection and criticality.
func TestSubjectAltName(t *testing.T) {
	values := []string{"dns:a.example", "b.example", "ip:192.0.2.1", "2001:db8::1", "email:x@example.com", "y@example.com", "uri:urn:ex:1", "https://example.com/p"}
	ext, err := SubjectAltName(values, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ext.Critical || !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
		t.Errorf("extension = %v critical %v", ext.Id, ext.Critical)
	}
	cert := certifyExtension(t, ext)
	got := fmt.Sprint(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
	want := "[a.example b.example] [192.0.2.1 2001:db8::1] [x@example.com y@example.com] [urn:ex:1 https://example.com/p]"
	if got != want {
		t.Errorf("names = %s, want %s", got, want)
	}
}

// certifyExtension issues a throwaway certificate with ext and parses it, so that crypto/x509
// decodes the extension.
func certifyExtension(t *testing.T, ext pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), ExtraExtensions: []pkix.Extension{ext}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestSubjectAltNameErrors checks values that must be rejected.
func TestSubjectAltNameErrors(t *testing.T) {
	for _, v := range []string{"", "dns:", "ip:300.1.1.1", "email:not an address", "uri:no-scheme", "dns:has space", "dns:zoë.example"} {
		if _, err := SubjectAltName([]string{v}, false); err == nil {
			t.Errorf("SubjectAltName(%q) succeeded, want an error", v)
		}
	}
}
