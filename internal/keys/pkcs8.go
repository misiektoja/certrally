package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // G505: hmacWithSHA1 is the default PBKDF2 function of PKCS#5.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
)

// Object identifiers of PBES2 (RFC 8018 appendix A and C).
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	// oidHMACWithSHA1 is the PBKDF2 function that applies when the parameters name none.
	oidHMACWithSHA1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
)

// prfs maps the PBKDF2 pseudorandom functions to their hashes.
var prfs = map[string]func() hash.Hash{
	oidHMACWithSHA1.String(): sha1.New,
	"1.2.840.113549.2.8":     sha256.New224,
	"1.2.840.113549.2.9":     sha256.New,
	"1.2.840.113549.2.10":    sha512.New384,
	"1.2.840.113549.2.11":    sha512.New,
	"1.2.840.113549.2.12":    sha512.New512_224,
	"1.2.840.113549.2.13":    sha512.New512_256,
}

// aesKeySizes maps the AES-CBC encryption schemes to their key sizes in bytes.
var aesKeySizes = map[string]int{
	"2.16.840.1.101.3.4.1.2":  16,
	"2.16.840.1.101.3.4.1.22": 24,
	"2.16.840.1.101.3.4.1.42": 32,
}

// errWrongPassword reports a key that does not decrypt with the given password.
var errWrongPassword = errors.New("cannot decrypt the private key: wrong password or damaged key")

// encryptedPrivateKeyInfo is the EncryptedPrivateKeyInfo of RFC 5958.
type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// pbes2Params are the parameters of PBES2.
type pbes2Params struct {
	KeyDerivation pkix.AlgorithmIdentifier
	Encryption    pkix.AlgorithmIdentifier
}

// pbkdf2Params are the parameters of PBKDF2. The salt is always given, never derived.
type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// isEncryptedPKCS8 reports whether der is an EncryptedPrivateKeyInfo rather than a PrivateKeyInfo,
// which starts with a version number instead of an algorithm.
func isEncryptedPKCS8(der []byte) bool {
	var info encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	return err == nil && len(rest) == 0
}

// decryptPKCS8 returns the PrivateKeyInfo that the EncryptedPrivateKeyInfo der protects with
// password. Only PBES2 with PBKDF2 and AES-CBC is supported.
func decryptPKCS8(der, password []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, errors.New("parse encrypted private key: not an EncryptedPrivateKeyInfo")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("encrypted private key uses %s, want PBES2 with PBKDF2 and AES as openssl pkcs8 -topk8 writes",
			info.Algorithm.Algorithm)
	}
	var params pbes2Params
	if rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return nil, errors.New("parse encrypted private key: malformed PBES2 parameters")
	}
	keySize, ok := aesKeySizes[params.Encryption.Algorithm.String()]
	if !ok {
		return nil, fmt.Errorf("encrypted private key uses cipher %s, want AES in CBC mode", params.Encryption.Algorithm)
	}
	var iv []byte
	rest, err := asn1.Unmarshal(params.Encryption.Parameters.FullBytes, &iv)
	if err != nil || len(rest) != 0 || len(iv) != aes.BlockSize {
		return nil, errors.New("parse encrypted private key: malformed AES parameters")
	}
	key, err := deriveKey(params.KeyDerivation, password, keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(info.Data) == 0 || len(info.Data)%aes.BlockSize != 0 {
		return nil, errors.New("parse encrypted private key: the encrypted data is not a whole number of blocks")
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, info.Data)
	return unpad(plain)
}

// deriveKey runs the PBKDF2 of kdf over password and returns a key of keySize bytes.
func deriveKey(kdf pkix.AlgorithmIdentifier, password []byte, keySize int) ([]byte, error) {
	if !kdf.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("encrypted private key derives its key with %s, want PBKDF2", kdf.Algorithm)
	}
	var params pbkdf2Params
	if rest, err := asn1.Unmarshal(kdf.Parameters.FullBytes, &params); err != nil || len(rest) != 0 {
		return nil, errors.New("parse encrypted private key: malformed PBKDF2 parameters")
	}
	if params.Iterations < 1 {
		return nil, errors.New("parse encrypted private key: the PBKDF2 iteration count is not positive")
	}
	if params.KeyLength != 0 && params.KeyLength != keySize {
		return nil, errors.New("parse encrypted private key: the PBKDF2 key length does not fit the cipher")
	}
	prf := oidHMACWithSHA1
	if params.PRF.Algorithm != nil {
		prf = params.PRF.Algorithm
	}
	newHash, ok := prfs[prf.String()]
	if !ok {
		return nil, fmt.Errorf("encrypted private key uses the PBKDF2 function %s, want an HMAC with SHA-1 or SHA-2", prf)
	}
	return pbkdf2.Key(newHash, string(password), params.Salt, params.Iterations, keySize)
}

// unpad removes the PKCS#7 padding of a decrypted block sequence.
func unpad(plain []byte) ([]byte, error) {
	n := int(plain[len(plain)-1])
	if n == 0 || n > aes.BlockSize || n > len(plain) {
		return nil, errWrongPassword
	}
	for _, b := range plain[len(plain)-n:] {
		if int(b) != n {
			return nil, errWrongPassword
		}
	}
	return plain[:len(plain)-n], nil
}
