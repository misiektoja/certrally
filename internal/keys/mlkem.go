package keys

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"crypto/sha3"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ML-KEM keys cannot sign, so a CA certifies them after an indirect proof of possession, by
// decryption. crypto/x509 does not encode them, so this file implements the PKCS#8 and
// SubjectPublicKeyInfo forms of RFC 9935.

// mlkemSeedSize is the size of the seed d || z that an ML-KEM key derives from (FIPS 203).
const mlkemSeedSize = 64

// mlkemParams is an ML-KEM parameter set that crypto/mlkem implements.
type mlkemParams struct {
	name string
	oid  asn1.ObjectIdentifier
	// k is the module rank, which sets the sizes of the keys.
	k        int
	fromSeed func(seed []byte) (crypto.Decapsulator, error)
	fromKey  func(encapsulationKey []byte) (crypto.PublicKey, error)
}

// Object identifiers of ML-KEM (RFC 9935 §3).
var (
	oidMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	oidMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// mlkemParameterSets lists ML-KEM-768 and ML-KEM-1024. crypto/mlkem has no ML-KEM-512.
var mlkemParameterSets = []*mlkemParams{
	{
		name: "ML-KEM-768",
		oid:  oidMLKEM768,
		k:    3,
		fromSeed: func(seed []byte) (crypto.Decapsulator, error) {
			return mlkem.NewDecapsulationKey768(seed)
		},
		fromKey: func(key []byte) (crypto.PublicKey, error) { return mlkem.NewEncapsulationKey768(key) },
	},
	{
		name: "ML-KEM-1024",
		oid:  oidMLKEM1024,
		k:    4,
		fromSeed: func(seed []byte) (crypto.Decapsulator, error) {
			return mlkem.NewDecapsulationKey1024(seed)
		},
		fromKey: func(key []byte) (crypto.PublicKey, error) { return mlkem.NewEncapsulationKey1024(key) },
	},
}

// errMLKEM512 reports an ML-KEM-512 key, which crypto/mlkem does not implement.
var errMLKEM512 = errors.New("ML-KEM-512 keys are not supported, use ML-KEM-768 or ML-KEM-1024")

// mlkemByOID returns the parameter set of an ML-KEM algorithm identifier. It reports false for
// other algorithms and returns an error for ML-KEM-512.
func mlkemByOID(oid asn1.ObjectIdentifier) (*mlkemParams, bool, error) {
	if oid.Equal(oidMLKEM512) {
		return nil, true, errMLKEM512
	}
	for _, p := range mlkemParameterSets {
		if oid.Equal(p.oid) {
			return p, true, nil
		}
	}
	return nil, false, nil
}

// mlkemKey returns the parameter set and the seed of an ML-KEM private key. It reports false for
// other keys.
func mlkemKey(key crypto.PrivateKey) (*mlkemParams, []byte, bool) {
	switch k := key.(type) {
	case *mlkem.DecapsulationKey768:
		return mlkemParameterSets[0], k.Bytes(), true
	case *mlkem.DecapsulationKey1024:
		return mlkemParameterSets[1], k.Bytes(), true
	}
	return nil, nil, false
}

// mlkemPublicKey returns the parameter set and the encoding of an ML-KEM public key. It reports
// false for other keys.
func mlkemPublicKey(pub crypto.PublicKey) (*mlkemParams, []byte, bool) {
	switch k := pub.(type) {
	case *mlkem.EncapsulationKey768:
		return mlkemParameterSets[0], k.Bytes(), true
	case *mlkem.EncapsulationKey1024:
		return mlkemParameterSets[1], k.Bytes(), true
	}
	return nil, nil, false
}

// marshalMLKEM encodes an ML-KEM private key as a PKCS#8 PrivateKeyInfo in the seed form of
// RFC 9935 §6, which every RFC 9935 implementation reads.
func marshalMLKEM(p *mlkemParams, seed []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(p.oid)
		})
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(seed)
			})
		})
	})
	return b.Bytes()
}

// pkcs8Info holds the fields of a PKCS#8 PrivateKeyInfo or OneAsymmetricKey that ML-KEM keys use.
type pkcs8Info struct {
	algorithm asn1.ObjectIdentifier
	// hasParameters is set when the AlgorithmIdentifier carries parameters.
	hasParameters bool
	privateKey    []byte
	// publicKey is the optional public key of a version 2 OneAsymmetricKey (RFC 5958).
	publicKey []byte
}

// readPKCS8 decodes the PrivateKeyInfo der. It reports false when der is not one.
func readPKCS8(der []byte) (*pkcs8Info, bool) {
	input := cryptobyte.String(der)
	var info, alg, privateKey cryptobyte.String
	var version int64
	out := &pkcs8Info{}
	if !input.ReadASN1(&info, cbasn1.SEQUENCE) || !input.Empty() ||
		!info.ReadASN1Integer(&version) || (version != 0 && version != 1) ||
		!info.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&out.algorithm) ||
		!info.ReadASN1(&privateKey, cbasn1.OCTET_STRING) {
		return nil, false
	}
	out.hasParameters = !alg.Empty()
	out.privateKey = privateKey
	if !info.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, false
	}
	var publicKey cryptobyte.String
	var hasPublicKey bool
	if !info.ReadOptionalASN1(&publicKey, &hasPublicKey, cbasn1.Tag(1).ContextSpecific()) || !info.Empty() {
		return nil, false
	}
	if hasPublicKey {
		// publicKey [1] IMPLICIT BIT STRING: the first byte counts the unused bits.
		if len(publicKey) == 0 || publicKey[0] != 0 {
			return nil, false
		}
		out.publicKey = publicKey[1:]
	}
	return out, true
}

// parseMLKEM decodes the ML-KEM private key of info, in any of the three forms of RFC 9935 §6:
// the seed, the expanded key or both. crypto/mlkem rebuilds a key only from its seed, so a key
// given as the expanded key alone is refused.
func parseMLKEM(p *mlkemParams, info *pkcs8Info) (crypto.Decapsulator, error) {
	if info.hasParameters {
		return nil, fmt.Errorf("an %s key must have no algorithm parameters", p.name)
	}
	s := cryptobyte.String(info.privateKey)
	var seed, expanded cryptobyte.String
	switch {
	case s.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific()):
		if !s.ReadASN1(&seed, cbasn1.Tag(0).ContextSpecific()) || !s.Empty() {
			return nil, fmt.Errorf("malformed %s private key", p.name)
		}
	case s.PeekASN1Tag(cbasn1.SEQUENCE):
		var both cryptobyte.String
		if !s.ReadASN1(&both, cbasn1.SEQUENCE) || !s.Empty() ||
			!both.ReadASN1(&seed, cbasn1.OCTET_STRING) || !both.ReadASN1(&expanded, cbasn1.OCTET_STRING) ||
			!both.Empty() {
			return nil, fmt.Errorf("malformed %s private key", p.name)
		}
	case s.PeekASN1Tag(cbasn1.OCTET_STRING):
		return nil, fmt.Errorf("the %s private key holds the expanded key without its seed, which cannot be read. "+
			"Generate a key that keeps its seed, as certrally keygen and openssl genpkey do", p.name)
	default:
		return nil, fmt.Errorf("malformed %s private key", p.name)
	}
	if len(seed) != mlkemSeedSize {
		return nil, fmt.Errorf("the %s seed is %d bytes, want %d", p.name, len(seed), mlkemSeedSize)
	}
	key, err := p.fromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("parse %s private key: %w", p.name, err)
	}
	encapsulationKey := key.Encapsulator().Bytes()
	if expanded != nil && !p.matchesExpanded(expanded, seed, encapsulationKey) {
		return nil, fmt.Errorf("the seed and the expanded key of the %s private key do not match", p.name)
	}
	if info.publicKey != nil && !bytes.Equal(info.publicKey, encapsulationKey) {
		return nil, fmt.Errorf("the public key in the %s private key does not match it", p.name)
	}
	return key, nil
}

// matchesExpanded checks an expanded decapsulation key against the key its seed derives. FIPS 203
// lays it out as dk_PKE || ek || H(ek) || z. crypto/mlkem does not expose dk_PKE, so the check covers
// the size and the other three parts.
func (p *mlkemParams) matchesExpanded(expanded, seed, encapsulationKey []byte) bool {
	pkeSize := 384 * p.k
	if len(expanded) != pkeSize+len(encapsulationKey)+64 {
		return false
	}
	rest := expanded[pkeSize:]
	h := sha3.Sum256(encapsulationKey)
	return bytes.Equal(rest[:len(encapsulationKey)], encapsulationKey) &&
		bytes.Equal(rest[len(encapsulationKey):len(encapsulationKey)+32], h[:]) &&
		bytes.Equal(rest[len(encapsulationKey)+32:], seed[32:])
}

// marshalMLKEMPublicKey encodes an ML-KEM public key as a SubjectPublicKeyInfo (RFC 9935 §4).
func marshalMLKEMPublicKey(p *mlkemParams, encapsulationKey []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(p.oid)
		})
		b.AddASN1BitString(encapsulationKey)
	})
	return b.Bytes()
}

// parseMLKEMPublicKey decodes an ML-KEM SubjectPublicKeyInfo. It reports false when spki holds
// another algorithm.
func parseMLKEMPublicKey(spki []byte) (crypto.PublicKey, bool, error) {
	input := cryptobyte.String(spki)
	var info, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	var bits asn1.BitString
	if !input.ReadASN1(&info, cbasn1.SEQUENCE) || !input.Empty() ||
		!info.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return nil, false, nil
	}
	p, ok, err := mlkemByOID(oid)
	if !ok || err != nil {
		return nil, ok, err
	}
	if !alg.Empty() || !info.ReadASN1BitString(&bits) || !info.Empty() || bits.BitLength%8 != 0 {
		return nil, true, fmt.Errorf("malformed %s public key", p.name)
	}
	pub, err := p.fromKey(bits.Bytes)
	if err != nil {
		return nil, true, fmt.Errorf("parse %s public key: %w", p.name, err)
	}
	return pub, true, nil
}
