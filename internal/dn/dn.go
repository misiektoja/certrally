// Package dn parses distinguished names and subject alternative names given on the command line.
package dn

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Attribute types accepted by keyword. Others can be given as a dotted OID.
var keywords = map[string]asn1.ObjectIdentifier{
	"CN":           {2, 5, 4, 3},
	"SERIALNUMBER": {2, 5, 4, 5},
	"C":            {2, 5, 4, 6},
	"L":            {2, 5, 4, 7},
	"ST":           {2, 5, 4, 8},
	"STREET":       {2, 5, 4, 9},
	"O":            {2, 5, 4, 10},
	"OU":           {2, 5, 4, 11},
	"POSTALCODE":   {2, 5, 4, 17},
	"UID":          {0, 9, 2342, 19200300, 100, 1, 1},
}

// ParseName parses an RFC 4514 string such as "CN=device-42,O=Example,C=PL" into a name whose
// attributes are encoded in the order the string implies.
//
// RFC 4514 writes the most specific RDN first, so the encoded order is the reverse of the string.
// Parsing the output of pkix.Name.String returns an equal name. Multi-valued RDNs and hex-encoded
// values are rejected because pkix.Name cannot represent them faithfully.
func ParseName(s string) (pkix.Name, error) {
	var name pkix.Name
	if strings.TrimSpace(s) == "" {
		return name, errors.New("empty distinguished name")
	}
	rdns, err := splitUnescaped(s, ',')
	if err != nil {
		return name, err
	}
	for _, rdn := range slices.Backward(rdns) {
		if parts, _ := splitUnescaped(rdn, '+'); len(parts) > 1 {
			return name, fmt.Errorf("multi-valued RDN %q is not supported", strings.TrimSpace(rdn))
		}
		atv, err := parseAttribute(rdn)
		if err != nil {
			return name, err
		}
		name.ExtraNames = append(name.ExtraNames, atv)
	}
	return name, nil
}

// parseAttribute parses one "type=value" pair.
func parseAttribute(s string) (pkix.AttributeTypeAndValue, error) {
	key, value, ok := strings.Cut(s, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" {
		return pkix.AttributeTypeAndValue{}, fmt.Errorf("malformed RDN %q, want type=value", strings.TrimSpace(s))
	}
	oid, err := attributeType(key)
	if err != nil {
		return pkix.AttributeTypeAndValue{}, err
	}
	v, err := unescapeValue(value)
	if err != nil {
		return pkix.AttributeTypeAndValue{}, fmt.Errorf("value of %s: %w", key, err)
	}
	if v == "" {
		return pkix.AttributeTypeAndValue{}, fmt.Errorf("empty value for %s", key)
	}
	return pkix.AttributeTypeAndValue{Type: oid, Value: v}, nil
}

// attributeType resolves a keyword or a dotted OID.
func attributeType(key string) (asn1.ObjectIdentifier, error) {
	if oid, ok := keywords[strings.ToUpper(key)]; ok {
		return oid, nil
	}
	if key[0] >= '0' && key[0] <= '9' {
		var oid asn1.ObjectIdentifier
		for part := range strings.SplitSeq(key, ".") {
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || strconv.Itoa(n) != part {
				return nil, fmt.Errorf("invalid attribute OID %q", key)
			}
			oid = append(oid, n)
		}
		if len(oid) < 2 {
			return nil, fmt.Errorf("invalid attribute OID %q", key)
		}
		return oid, nil
	}
	return nil, fmt.Errorf("unknown attribute type %q, "+
		"use one of CN, O, OU, C, L, ST, STREET, POSTALCODE, SERIALNUMBER, UID or a dotted OID", key)
}

// splitUnescaped splits s at every sep that is not escaped with a backslash or inside double quotes.
func splitUnescaped(s string, sep byte) ([]string, error) {
	var parts []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		case sep:
			if !quoted {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote in distinguished name")
	}
	return append(parts, s[start:]), nil
}

// unescapeValue decodes RFC 4514 escapes. Unescaped leading and trailing spaces are removed and
// surrounding double quotes, an older RFC 1779 form, are accepted.
func unescapeValue(s string) (string, error) {
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, "#") {
		return "", errors.New("hex-encoded values are not supported")
	}
	if strings.HasPrefix(s, `"`) {
		trimmed := strings.TrimRight(s, " ")
		if len(trimmed) < 2 || !strings.HasSuffix(trimmed, `"`) {
			return "", errors.New("unterminated quote")
		}
		s = trimmed[1 : len(trimmed)-1]
		return unescapeBody(s, false)
	}
	return unescapeBody(s, true)
}

// unescapeBody decodes backslash escapes. When trimTrailing is set, trailing spaces that are not
// escaped are removed.
func unescapeBody(s string, trimTrailing bool) (string, error) {
	var b []byte
	keep := 0 // length of b that must survive trailing-space trimming
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b = append(b, c)
			if c != ' ' {
				keep = len(b)
			}
			continue
		}
		if i+1 >= len(s) {
			return "", errors.New("trailing backslash")
		}
		if i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, _ := hex.DecodeString(s[i+1 : i+3])
			b = append(b, v[0])
			i += 2
		} else {
			b = append(b, s[i+1])
			i++
		}
		keep = len(b)
	}
	if trimTrailing {
		b = b[:keep]
	}
	if !utf8.Valid(b) {
		return "", errors.New("value is not valid UTF-8")
	}
	return string(b), nil
}

// isHex reports whether c is a hexadecimal digit.
func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// oidSubjectAltName identifies the subjectAltName extension (RFC 5280 §4.2.1.6).
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// SubjectAltName builds a subjectAltName extension from values such as "dns:example.com",
// "ip:192.0.2.1", "email:user@example.com" and "uri:https://example.com". A value without a prefix
// is an IP address if it parses as one, an email address if it contains @, a URI if it contains ://
// and a DNS name otherwise. RFC 5280 requires the extension to be critical when the subject is
// empty, which critical selects.
func SubjectAltName(values []string, critical bool) (pkix.Extension, error) {
	names := make([]asn1.RawValue, 0, len(values))
	for _, v := range values {
		n, err := generalName(v)
		if err != nil {
			return pkix.Extension{}, err
		}
		names = append(names, n)
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encode subjectAltName: %w", err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Critical: critical, Value: der}, nil
}

// Prefixes of --san values.
const (
	kindDNS   = "dns"
	kindIP    = "ip"
	kindEmail = "email"
	kindURI   = "uri"
)

// GeneralName tags from RFC 5280 §4.2.1.6.
const (
	tagRFC822Name = 1
	tagDNSName    = 2
	tagURI        = 6
	tagIPAddress  = 7
)

// generalName encodes one subjectAltName value.
func generalName(v string) (asn1.RawValue, error) {
	kind, value, hasKind := strings.Cut(v, ":")
	if !hasKind || !isKnownKind(kind) {
		kind, value = guessKind(v), v
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return asn1.RawValue{}, fmt.Errorf("empty subjectAltName value in %q", v)
	}
	switch strings.ToLower(kind) {
	case kindDNS:
		if strings.ContainsAny(value, " /@") || !isASCII(value) {
			return asn1.RawValue{}, fmt.Errorf("invalid DNS name %q", value)
		}
		return contextString(tagDNSName, value), nil
	case kindIP:
		ip := net.ParseIP(value)
		if ip == nil {
			return asn1.RawValue{}, fmt.Errorf("invalid IP address %q", value)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tagIPAddress, Bytes: ip}, nil
	case kindEmail:
		if _, err := mail.ParseAddress(value); err != nil || !isASCII(value) {
			return asn1.RawValue{}, fmt.Errorf("invalid email address %q", value)
		}
		return contextString(tagRFC822Name, value), nil
	default: // kindURI
		u, err := url.Parse(value)
		if err != nil || u.Scheme == "" || !isASCII(value) {
			return asn1.RawValue{}, fmt.Errorf("invalid URI %q", value)
		}
		return contextString(tagURI, value), nil
	}
}

// isKnownKind reports whether kind is a supported subjectAltName prefix.
func isKnownKind(kind string) bool {
	switch strings.ToLower(kind) {
	case kindDNS, kindIP, kindEmail, kindURI:
		return true
	}
	return false
}

// guessKind picks the subjectAltName type of a value given without a prefix.
func guessKind(v string) string {
	switch {
	case net.ParseIP(v) != nil:
		return kindIP
	case strings.Contains(v, "://"):
		return kindURI
	case strings.Contains(v, "@"):
		return kindEmail
	}
	return kindDNS
}

// contextString encodes an IA5String GeneralName with an implicit context-specific tag.
func contextString(tag int, s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: []byte(s)}
}

// isASCII reports whether s fits the IA5String character set that these GeneralName forms use.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
