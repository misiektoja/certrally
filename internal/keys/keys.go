// Package keys generates, encodes and describes the private keys certrally enrolls.
package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
)

// Type is a key algorithm certrally can generate.
type Type struct {
	// Name is the value of the --key-type flag.
	Name string
	// Signs is false for ML-KEM, whose keys prove possession by decryption instead.
	Signs bool
	// generate creates a new key of this type: a crypto.Signer or, for ML-KEM, a crypto.Decapsulator.
	generate func() (crypto.PrivateKey, error)
	// oid and params identify the algorithm in a SubjectPublicKeyInfo. params is DER, nil when the
	// algorithm has none.
	oid    asn1.ObjectIdentifier
	params []byte
}

// Algorithm returns the SubjectPublicKeyInfo algorithm of keys of this type: its object identifier
// and its DER parameters, nil when it has none. The RSA algorithm does not carry the key size.
func (t Type) Algorithm() (asn1.ObjectIdentifier, []byte) {
	return t.oid, t.params
}

// TypeForAlgorithm returns the first key type, in the order of TypeNames, whose SubjectPublicKeyInfo
// algorithm is oid with the DER parameters params. Empty params match any parameters, so they select
// ECDSA P-256 for an EC key. RSA selects rsa-2048, since the algorithm carries no key size.
func TypeForAlgorithm(oid asn1.ObjectIdentifier, params []byte) (Type, bool) {
	for _, t := range types {
		if t.oid.Equal(oid) && (len(params) == 0 || bytes.Equal(params, t.params)) {
			return t, true
		}
	}
	return Type{}, false
}

// Object identifiers and parameters of the SubjectPublicKeyInfo algorithms of the key types.
var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidMLDSA44     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// asn1NULL is the parameters of rsaEncryption.
	asn1NULL = []byte{0x05, 0x00}
)

// namedCurve returns the DER namedCurve parameters of an ECDSA key on the curve oid.
func namedCurve(oid asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return der
}

// DefaultType is the key type generated when none is requested. ECDSA P-256 is accepted by
// practically every CA.
const DefaultType = "ecdsa-p256"

// types lists the generated key types in the order help shows them.
var types = buildTypes()

// buildTypes returns the classical, ML-DSA, composite ML-DSA and ML-KEM key types.
func buildTypes() []Type {
	composites := compositemldsa.Algorithms()
	out := make([]Type, 0, 12+len(composites))
	p256 := namedCurve(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	p384 := namedCurve(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	p521 := namedCurve(asn1.ObjectIdentifier{1, 3, 132, 0, 35})
	out = append(out, []Type{
		{"ecdsa-p256", true, ecdsaGenerator(elliptic.P256()), oidECPublicKey, p256},
		{"ecdsa-p384", true, ecdsaGenerator(elliptic.P384()), oidECPublicKey, p384},
		{"ecdsa-p521", true, ecdsaGenerator(elliptic.P521()), oidECPublicKey, p521},
		{"ed25519", true, func() (crypto.PrivateKey, error) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			return key, err
		}, oidEd25519, nil},
		{"rsa-2048", true, rsaGenerator(2048), oidRSA, asn1NULL},
		{"rsa-3072", true, rsaGenerator(3072), oidRSA, asn1NULL},
		{"rsa-4096", true, rsaGenerator(4096), oidRSA, asn1NULL},
		{"ml-dsa-44", true, mldsaGenerator(mldsa.MLDSA44()), oidMLDSA44, nil},
		{"ml-dsa-65", true, mldsaGenerator(mldsa.MLDSA65()), oidMLDSA65, nil},
		{"ml-dsa-87", true, mldsaGenerator(mldsa.MLDSA87()), oidMLDSA87, nil},
	}...)
	for _, alg := range composites {
		out = append(out, Type{strings.ToLower(alg.String()), true, func() (crypto.PrivateKey, error) {
			return compositemldsa.GenerateKey(alg)
		}, alg.OID(), nil})
	}
	return append(out,
		Type{"ml-kem-768", false, func() (crypto.PrivateKey, error) { return mlkem.GenerateKey768() }, oidMLKEM768, nil},
		Type{"ml-kem-1024", false, func() (crypto.PrivateKey, error) { return mlkem.GenerateKey1024() }, oidMLKEM1024, nil},
	)
}

// ecdsaGenerator returns a generator for ECDSA keys on curve.
func ecdsaGenerator(curve elliptic.Curve) func() (crypto.PrivateKey, error) {
	return func() (crypto.PrivateKey, error) { return ecdsa.GenerateKey(curve, rand.Reader) }
}

// rsaGenerator returns a generator for RSA keys of the given size.
func rsaGenerator(bits int) func() (crypto.PrivateKey, error) {
	return func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, bits) }
}

// mldsaGenerator returns a generator for ML-DSA keys with the given parameters.
func mldsaGenerator(params mldsa.Parameters) func() (crypto.PrivateKey, error) {
	return func() (crypto.PrivateKey, error) { return mldsa.GenerateKey(params) }
}

// TypeNames returns the names accepted by Generate.
func TypeNames() []string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = t.Name
	}
	return names
}

// SigningTypeNames returns the names of the key types whose keys can sign, which GenerateSigner accepts.
func SigningTypeNames() []string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		if t.Signs {
			names = append(names, t.Name)
		}
	}
	return names
}

// LookupType returns the named key type. Names are matched without regard to case.
func LookupType(name string) (Type, error) {
	for _, t := range types {
		if strings.EqualFold(t.Name, name) {
			return t, nil
		}
	}
	return Type{}, fmt.Errorf("unknown key type %q, want one of %s", name, strings.Join(TypeNames(), ", "))
}

// Generate creates a key of the named type. Names are matched without regard to case. The key is a
// crypto.Signer, or a crypto.Decapsulator for ML-KEM.
func Generate(name string) (crypto.PrivateKey, error) {
	t, err := LookupType(name)
	if err != nil {
		return nil, err
	}
	key, err := t.generate()
	if err != nil {
		return nil, fmt.Errorf("generate %s key: %w", t.Name, err)
	}
	return key, nil
}

// GenerateSigner creates a key of the named type, which must be one that can sign.
func GenerateSigner(name string) (crypto.Signer, error) {
	t, err := LookupType(name)
	if err != nil {
		return nil, err
	}
	if !t.Signs {
		return nil, fmt.Errorf("%s keys cannot sign, want one of %s", t.Name, strings.Join(SigningTypeNames(), ", "))
	}
	key, err := Generate(name)
	if err != nil {
		return nil, err
	}
	return Signer(key)
}

// Public returns the public key of a key that Generate or Parse returned.
func Public(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case crypto.Signer:
		return k.Public()
	case crypto.Decapsulator:
		return k.Encapsulator()
	}
	return nil
}

// Signer returns key as a crypto.Signer. The error for a key that cannot sign, such as an ML-KEM
// key, names its algorithm.
func Signer(key crypto.PrivateKey) (crypto.Signer, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		if pub := Public(key); pub != nil {
			return nil, fmt.Errorf("an %s key cannot sign", Describe(pub))
		}
		return nil, fmt.Errorf("a %T cannot sign", key)
	}
	return signer, nil
}

// Describe names the algorithm of a public key for display, for example "ECDSA P-256" or "ML-DSA-65".
func Describe(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	case *mldsa.PublicKey:
		return k.Parameters().String()
	case *compositemldsa.PublicKey:
		return k.Algorithm().String()
	}
	if p, _, ok := mlkemPublicKey(pub); ok {
		return p.name
	}
	return fmt.Sprintf("%T", pub)
}

// Marshal encodes a private key as unencrypted PKCS#8 DER. An ML-KEM key is written in the seed
// form of RFC 9935.
func Marshal(key crypto.PrivateKey) ([]byte, error) {
	if p, seed, ok := mlkemKey(key); ok {
		return marshalMLKEM(p, seed)
	}
	der, err := compositex509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return der, nil
}

// MarshalPEM encodes a private key as an unencrypted PKCS#8 PEM block.
func MarshalPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := Marshal(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKey encodes a public key as a DER SubjectPublicKeyInfo, including ML-DSA, composite
// ML-DSA and ML-KEM keys.
func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	if p, encapsulationKey, ok := mlkemPublicKey(pub); ok {
		return marshalMLKEMPublicKey(p, encapsulationKey)
	}
	der, err := compositex509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	return der, nil
}

// ErrEncrypted reports an encrypted PKCS#8 private key, which Parse cannot decode without its
// password. The error Parse returns for one wraps it. ParseEncrypted decodes the key.
var ErrEncrypted = errors.New("the private key is encrypted")

// pemEncryptedPKCS8 is the PEM block type of an encrypted PKCS#8 key.
const pemEncryptedPKCS8 = "ENCRYPTED PRIVATE KEY"

// Parse decodes a private key from PEM or DER. It accepts PKCS#8 for every supported algorithm,
// including ML-DSA, composite ML-DSA and ML-KEM, and the older SEC 1 and PKCS#1 forms for ECDSA and
// RSA. The key is a crypto.Signer, or a crypto.Decapsulator for ML-KEM. For an encrypted PKCS#8 key
// it returns an error that wraps ErrEncrypted. Keys encrypted the legacy way, with Proc-Type PEM
// headers, are refused.
func Parse(data []byte) (crypto.PrivateKey, error) {
	der, blockType := data, ""
	if block, _ := pem.Decode(data); block != nil {
		if block.Headers["Proc-Type"] != "" {
			return nil, errors.New("encrypted private keys are not supported")
		}
		der, blockType = block.Bytes, block.Type
	}

	switch blockType {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		return parsePKCS8(der)
	case "":
		if isEncryptedPKCS8(der) {
			return nil, ErrEncrypted
		}
		return parsePKCS8(der)
	case pemEncryptedPKCS8:
		return nil, ErrEncrypted
	default:
		return nil, fmt.Errorf("unexpected PEM block %q, want a private key", blockType)
	}
}

// parsePKCS8 decodes an unencrypted PKCS#8 private key.
func parsePKCS8(der []byte) (crypto.PrivateKey, error) {
	if info, ok := readPKCS8(der); ok {
		p, isMLKEM, err := mlkemByOID(info.algorithm)
		if err != nil {
			return nil, err
		}
		if isMLKEM {
			return parseMLKEM(p, info)
		}
	}
	key, err := compositex509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return Signer(key)
}

// ParseEncrypted decodes an encrypted PKCS#8 private key from PEM or DER with its password. It
// accepts PBES2 with PBKDF2 and AES in CBC mode, the form that openssl pkcs8 -topk8 writes.
func ParseEncrypted(data, password []byte) (crypto.PrivateKey, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != pemEncryptedPKCS8 {
			return nil, fmt.Errorf("unexpected PEM block %q, want %s", block.Type, pemEncryptedPKCS8)
		}
		der = block.Bytes
	}
	plain, err := decryptPKCS8(der, password)
	if err != nil {
		return nil, err
	}
	if info, ok := readPKCS8(plain); ok {
		// An ML-KEM key reports its own errors, such as ML-KEM-512, since the password was right.
		if p, isMLKEM, err := mlkemByOID(info.algorithm); isMLKEM {
			if err != nil {
				return nil, err
			}
			return parseMLKEM(p, info)
		}
	}
	key, err := compositex509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		// A wrong password usually leaves padding that passes by chance only once in 256 tries.
		return nil, errWrongPassword
	}
	return Signer(key)
}

// CertificateKey returns the public key that cert certifies. crypto/x509 leaves the key of a
// composite ML-DSA or an ML-KEM certificate nil, so it is decoded here.
func CertificateKey(cert *x509.Certificate) (crypto.PublicKey, error) {
	if cert.PublicKey != nil {
		return cert.PublicKey, nil
	}
	if pub, isMLKEM, err := parseMLKEMPublicKey(cert.RawSubjectPublicKeyInfo); isMLKEM {
		if err != nil {
			return nil, fmt.Errorf("certificate public key: %w", err)
		}
		return pub, nil
	}
	pub, err := compositex509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("certificate public key: %w", err)
	}
	return pub, nil
}
