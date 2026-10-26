// Package keys generates, encodes and describes the private keys certrally enrolls.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	// generate creates a new key of this type.
	generate func() (crypto.Signer, error)
}

// DefaultType is the key type generated when none is requested. ECDSA P-256 is accepted by
// practically every CA.
const DefaultType = "ecdsa-p256"

// types lists the generated key types in the order help shows them.
var types = buildTypes()

// buildTypes returns the classical, ML-DSA and composite ML-DSA key types.
func buildTypes() []Type {
	composites := compositemldsa.Algorithms()
	out := make([]Type, 0, 10+len(composites))
	out = append(out, []Type{
		{"ecdsa-p256", ecdsaGenerator(elliptic.P256())},
		{"ecdsa-p384", ecdsaGenerator(elliptic.P384())},
		{"ecdsa-p521", ecdsaGenerator(elliptic.P521())},
		{"ed25519", func() (crypto.Signer, error) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			return key, err
		}},
		{"rsa-2048", rsaGenerator(2048)},
		{"rsa-3072", rsaGenerator(3072)},
		{"rsa-4096", rsaGenerator(4096)},
		{"ml-dsa-44", mldsaGenerator(mldsa.MLDSA44())},
		{"ml-dsa-65", mldsaGenerator(mldsa.MLDSA65())},
		{"ml-dsa-87", mldsaGenerator(mldsa.MLDSA87())},
	}...)
	for _, alg := range composites {
		out = append(out, Type{strings.ToLower(alg.String()), func() (crypto.Signer, error) {
			return compositemldsa.GenerateKey(alg)
		}})
	}
	return out
}

// ecdsaGenerator returns a generator for ECDSA keys on curve.
func ecdsaGenerator(curve elliptic.Curve) func() (crypto.Signer, error) {
	return func() (crypto.Signer, error) { return ecdsa.GenerateKey(curve, rand.Reader) }
}

// rsaGenerator returns a generator for RSA keys of the given size.
func rsaGenerator(bits int) func() (crypto.Signer, error) {
	return func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, bits) }
}

// mldsaGenerator returns a generator for ML-DSA keys with the given parameters.
func mldsaGenerator(params mldsa.Parameters) func() (crypto.Signer, error) {
	return func() (crypto.Signer, error) { return mldsa.GenerateKey(params) }
}

// TypeNames returns the names accepted by Generate.
func TypeNames() []string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = t.Name
	}
	return names
}

// Generate creates a key of the named type. Names are matched without regard to case.
func Generate(name string) (crypto.Signer, error) {
	for _, t := range types {
		if strings.EqualFold(t.Name, name) {
			key, err := t.generate()
			if err != nil {
				return nil, fmt.Errorf("generate %s key: %w", t.Name, err)
			}
			return key, nil
		}
	}
	return nil, fmt.Errorf("unknown key type %q, want one of %s", name, strings.Join(TypeNames(), ", "))
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
	return fmt.Sprintf("%T", pub)
}

// Marshal encodes a private key as unencrypted PKCS#8 DER.
func Marshal(key crypto.Signer) ([]byte, error) {
	der, err := compositex509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	return der, nil
}

// MarshalPEM encodes a private key as an unencrypted PKCS#8 PEM block.
func MarshalPEM(key crypto.Signer) ([]byte, error) {
	der, err := Marshal(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ErrEncrypted reports an encrypted PKCS#8 private key, which Parse cannot decode without its
// password. The error Parse returns for one wraps it. ParseEncrypted decodes the key.
var ErrEncrypted = errors.New("the private key is encrypted")

// pemEncryptedPKCS8 is the PEM block type of an encrypted PKCS#8 key.
const pemEncryptedPKCS8 = "ENCRYPTED PRIVATE KEY"

// Parse decodes a private key from PEM or DER. It accepts PKCS#8 for every supported algorithm,
// including ML-DSA and composite ML-DSA, and the older SEC 1 and PKCS#1 forms for ECDSA and RSA.
// For an encrypted PKCS#8 key it returns an error that wraps ErrEncrypted. Keys encrypted the
// legacy way, with Proc-Type PEM headers, are refused.
func Parse(data []byte) (crypto.Signer, error) {
	der, blockType := data, ""
	if block, _ := pem.Decode(data); block != nil {
		if block.Headers["Proc-Type"] != "" {
			return nil, errors.New("encrypted private keys are not supported")
		}
		der, blockType = block.Bytes, block.Type
	}

	var key any
	var err error
	switch blockType {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(der)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(der)
	case "PRIVATE KEY":
		key, err = compositex509.ParsePKCS8PrivateKey(der)
	case "":
		if isEncryptedPKCS8(der) {
			return nil, ErrEncrypted
		}
		key, err = compositex509.ParsePKCS8PrivateKey(der)
	case pemEncryptedPKCS8:
		return nil, ErrEncrypted
	default:
		return nil, fmt.Errorf("unexpected PEM block %q, want a private key", blockType)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return asSigner(key)
}

// ParseEncrypted decodes an encrypted PKCS#8 private key from PEM or DER with its password. It
// accepts PBES2 with PBKDF2 and AES in CBC mode, the form that openssl pkcs8 -topk8 writes.
func ParseEncrypted(data, password []byte) (crypto.Signer, error) {
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
	key, err := compositex509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		// A wrong password usually leaves padding that passes by chance only once in 256 tries.
		return nil, errWrongPassword
	}
	return asSigner(key)
}

// asSigner returns key as a crypto.Signer.
func asSigner(key any) (crypto.Signer, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a %T cannot sign", key)
	}
	return signer, nil
}

// CertificateKey returns the public key that cert certifies. crypto/x509 leaves the key of a
// composite ML-DSA certificate nil, so it is decoded here.
func CertificateKey(cert *x509.Certificate) (crypto.PublicKey, error) {
	if cert.PublicKey != nil {
		return cert.PublicKey, nil
	}
	pub, err := compositex509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("certificate public key: %w", err)
	}
	return pub, nil
}
