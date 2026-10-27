package cli

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
)

// Names of the enroll flags that shape the certificate template beyond the names.
const (
	flagKeyUsage     = "key-usage"
	flagExtKeyUsage  = "ext-key-usage"
	flagTemplateCert = "template-cert"
)

// Extension identifiers of RFC 5280 §4.2.1.3 and §4.2.1.12.
var (
	oidKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// keyUsageNames lists the --key-usage names in the bit order of the RFC 5280 §4.2.1.3 KeyUsage.
var keyUsageNames = []string{
	"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
	"keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
}

// contentCommitment is the name that X.509 (2008) gives the nonRepudiation bit.
const contentCommitment = "contentCommitment"

// keyPurpose is an --ext-key-usage name and the KeyPurposeId it stands for.
type keyPurpose struct {
	name string
	oid  asn1.ObjectIdentifier
}

// oidKeyPurposeCMCRA is the id-kp-cmcRA extended key usage of a registration authority.
var oidKeyPurposeCMCRA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 28}

// keyPurposes lists the --ext-key-usage names of RFC 5280 §4.2.1.12 and the registration authority
// purpose of RFC 6402 §2.10.
var keyPurposes = []keyPurpose{
	{"serverAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
	{"clientAuth", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}},
	{"codeSigning", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}},
	{"emailProtection", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}},
	{"timeStamping", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}},
	{"ocspSigning", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}},
	{"anyExtendedKeyUsage", asn1.ObjectIdentifier{2, 5, 29, 37, 0}},
	{"cmcRA", oidKeyPurposeCMCRA},
}

// keyPurposeNames lists the --ext-key-usage names in the order of keyPurposes.
var keyPurposeNames = func() []string {
	names := make([]string, 0, len(keyPurposes))
	for _, p := range keyPurposes {
		names = append(names, p.name)
	}
	return names
}()

// templateShape holds the parts of the certificate template that --template-cert, --key-usage and
// --ext-key-usage set. A nil field leaves that part to the other flags or out of the request.
type templateShape struct {
	// subject is the subject copied from the template certificate, nil when it is empty or
	// --subject replaces it.
	subject *pkix.Name
	// san is the subjectAltName copied from the template certificate, nil when it has none or --san
	// replaces it.
	san         *pkix.Extension
	keyUsage    *pkix.Extension
	extKeyUsage *pkix.Extension
}

// readShape reads --template-cert and encodes --key-usage and --ext-key-usage, which replace the
// extensions copied from the template certificate.
func (o *enrollOptions) readShape() (*templateShape, error) {
	shape := &templateShape{}
	if o.templateCert != "" {
		if err := shape.copyCertificate(o.templateCert, o.subject == "", len(o.sans) == 0); err != nil {
			return nil, err
		}
	}
	if len(o.keyUsage) > 0 {
		names, err := splitNames(flagKeyUsage, o.keyUsage)
		if err != nil {
			return nil, err
		}
		ext, err := keyUsageExtension(names)
		if err != nil {
			return nil, err
		}
		shape.keyUsage = &ext
	}
	if len(o.extKeyUsage) > 0 {
		values, err := splitNames(flagExtKeyUsage, o.extKeyUsage)
		if err != nil {
			return nil, err
		}
		ext, err := extKeyUsageExtension(values)
		if err != nil {
			return nil, err
		}
		shape.extKeyUsage = &ext
	}
	return shape, nil
}

// copyCertificate copies the keyUsage and extendedKeyUsage of the first certificate in path, and
// its subject and subjectAltName when withSubject and withSAN ask for them.
func (s *templateShape) copyCertificate(path string, withSubject, withSAN bool) error {
	certs, err := pemfile.ReadCertificates(path)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("--template-cert: %s holds no certificate", path)
	}
	cert := certs[0]
	if withSubject {
		subject, err := copySubject(cert)
		if err != nil {
			return fmt.Errorf("--template-cert: %s: %w", path, err)
		}
		s.subject = subject
	}
	if withSAN {
		s.san = certExtension(cert, oidSubjectAltName)
	}
	s.keyUsage = certExtension(cert, oidKeyUsage)
	s.extKeyUsage = certExtension(cert, oidExtKeyUsage)
	return nil
}

// copySubject returns the subject of cert with its attributes in the encoded order, or nil for an
// empty subject. It refuses a multi-valued RDN, which pkix.Name cannot represent.
func copySubject(cert *x509.Certificate) (*pkix.Name, error) {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(cert.RawSubject, &rdns); err != nil || len(rest) > 0 {
		return nil, errors.New("the subject cannot be decoded")
	}
	if len(rdns) == 0 {
		return nil, nil
	}
	if slices.ContainsFunc(rdns, func(rdn pkix.RelativeDistinguishedNameSET) bool { return len(rdn) > 1 }) {
		return nil, errors.New("the subject has a multi-valued RDN, which certrally cannot copy, so give --subject")
	}
	// ExtraNames alone are encoded in their order, one attribute per RDN.
	return &pkix.Name{ExtraNames: slices.Clone(cert.Subject.Names)}, nil
}

// certExtension returns a copy of the extension of cert with the identifier id, or nil.
func certExtension(cert *x509.Certificate, id asn1.ObjectIdentifier) *pkix.Extension {
	i := slices.IndexFunc(cert.Extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(id) })
	if i < 0 {
		return nil
	}
	ext := cert.Extensions[i]
	ext.Value = slices.Clone(ext.Value)
	return &ext
}

// splitNames splits the comma-separated values of a repeatable flag into their items. An empty item
// is an error, because it usually means a mistyped list.
func splitNames(flag string, values []string) ([]string, error) {
	var items []string
	for _, v := range values {
		for item := range strings.SplitSeq(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				return nil, fmt.Errorf("--%s %q holds an empty name", flag, v)
			}
			items = append(items, item)
		}
	}
	return items, nil
}

// keyUsageExtension encodes key usage names as a critical keyUsage extension, as RFC 5280 §4.2.1.3
// recommends. Names are matched without regard to case.
func keyUsageExtension(names []string) (pkix.Extension, error) {
	// DER encodes a named bit list without its trailing zero bits (X.690 §11.2.2).
	var bits [2]byte
	length := 0
	for _, name := range names {
		bit := slices.IndexFunc(keyUsageNames, func(n string) bool { return strings.EqualFold(n, name) })
		if strings.EqualFold(name, contentCommitment) {
			bit = 1
		}
		if bit < 0 {
			return pkix.Extension{}, fmt.Errorf("invalid --key-usage %q, want one of %s or %s",
				name, strings.Join(keyUsageNames, ", "), contentCommitment)
		}
		bits[bit/8] |= 0x80 >> (bit % 8)
		length = max(length, bit+1)
	}
	der, err := asn1.Marshal(asn1.BitString{Bytes: bits[:(length+7)/8], BitLength: length})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode keyUsage: %w", err)
	}
	return pkix.Extension{Id: oidKeyUsage, Critical: true, Value: der}, nil
}

// extKeyUsageExtension encodes key purpose names and dotted OIDs as a non-critical extendedKeyUsage
// extension. Names are matched without regard to case and a purpose given twice is sent once.
func extKeyUsageExtension(values []string) (pkix.Extension, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(values))
	for _, v := range values {
		oid, err := parseKeyPurpose(v)
		if err != nil {
			return pkix.Extension{}, err
		}
		if !slices.ContainsFunc(oids, oid.Equal) {
			oids = append(oids, oid)
		}
	}
	der, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode extendedKeyUsage: %w", err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Value: der}, nil
}

// parseKeyPurpose returns the KeyPurposeId of an --ext-key-usage name or dotted OID.
func parseKeyPurpose(v string) (asn1.ObjectIdentifier, error) {
	i := slices.IndexFunc(keyPurposes, func(p keyPurpose) bool { return strings.EqualFold(p.name, v) })
	switch {
	case i >= 0:
		return keyPurposes[i].oid, nil
	case strings.Contains(v, "."):
		oid, err := dn.ParseOID(v)
		if err != nil {
			return nil, fmt.Errorf("--ext-key-usage: %w", err)
		}
		return oid, nil
	}
	return nil, fmt.Errorf("invalid --ext-key-usage %q, want one of %s or a dotted OID",
		v, strings.Join(keyPurposeNames, ", "))
}

// templateExtensions returns the subjectAltName, keyUsage and extendedKeyUsage extensions of the
// request. hasSubject says whether the request names a subject, which decides whether the
// subjectAltName must be critical.
func (o *enrollOptions) templateExtensions(shape *templateShape, hasSubject bool) ([]pkix.Extension, error) {
	extensions, err := sanExtensions(o.sans, hasSubject)
	if err != nil {
		return nil, err
	}
	if shape.san != nil {
		san := *shape.san
		// RFC 5280 §4.2.1.6 ties the criticality to the subject of the new request, which
		// --subject may have changed.
		san.Critical = !hasSubject
		extensions = append(extensions, san)
	}
	for _, ext := range []*pkix.Extension{shape.keyUsage, shape.extKeyUsage} {
		if ext != nil {
			extensions = append(extensions, *ext)
		}
	}
	return extensions, nil
}

// listCompletion offers values for a comma-separated flag. It completes the item after the last
// comma and leaves out the items already typed.
func listCompletion(values []string) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cut := strings.LastIndex(toComplete, ",") + 1
		typed := strings.Split(toComplete[:cut], ",")
		completions := make([]string, 0, len(values))
		for _, v := range values {
			if !slices.ContainsFunc(typed, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), v) }) {
				completions = append(completions, toComplete[:cut]+v)
			}
		}
		return completions, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
}
