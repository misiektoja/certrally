package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// TestGenerateRoundTrip checks that every key type generates, encodes and parses back unchanged.
func TestGenerateRoundTrip(t *testing.T) {
	for _, name := range TypeNames() {
		// Larger RSA keys share the code path of rsa-2048 and take seconds to generate.
		if name == "rsa-3072" || name == "rsa-4096" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key, err := Generate(strings.ToUpper(name))
			if err != nil {
				t.Fatal(err)
			}
			data, err := MarshalPEM(key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(parsed.Public()) {
				t.Error("parsed key differs")
			}
			if Describe(key.Public()) == "" {
				t.Error("no description")
			}
		})
	}
}

// TestDescribe checks the names shown for common key types.
func TestDescribe(t *testing.T) {
	for name, want := range map[string]string{"ecdsa-p384": "ECDSA P-384", "ed25519": "Ed25519", "ml-dsa-87": "ML-DSA-87"} {
		key, err := Generate(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := Describe(key.Public()); got != want {
			t.Errorf("Describe(%s) = %q, want %q", name, got, want)
		}
	}
}

// TestParseLegacyForms checks SEC 1 and DER input, the rejection of foreign blocks and keys encrypted
// the legacy way, and ErrEncrypted for an encrypted PKCS#8 block.
func TestParseLegacyForms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"SEC 1 PEM":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"PKCS#8 DER": pkcs8,
	} {
		parsed, err := Parse(data)
		if err != nil || !key.PublicKey.Equal(parsed.Public()) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, data := range map[string][]byte{
		"encrypted":   pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: pkcs8}),
		"certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pkcs8}),
		"garbage":     []byte("not a key"),
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
	if _, err := Parse(pem.EncodeToMemory(&pem.Block{Type: pemEncryptedPKCS8, Bytes: pkcs8})); !errors.Is(err, ErrEncrypted) {
		t.Errorf("encrypted: error = %v, want ErrEncrypted", err)
	}
	legacy := pem.EncodeToMemory(&pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"},
		Bytes:   sec1,
	})
	if _, err := Parse(legacy); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("legacy: error = %v, want not supported", err)
	}
}

// TestGenerateUnknown checks the error for an unknown key type.
func TestGenerateUnknown(t *testing.T) {
	if _, err := Generate("dsa-1024"); err == nil || !strings.Contains(err.Error(), "unknown key type") {
		t.Errorf("Generate(dsa-1024) error = %v", err)
	}
}

// Encrypted PKCS#8 forms of one ECDSA P-256 key, written by openssl pkcs8 -topk8 with the password
// fixturePassword, and the SubjectPublicKeyInfo of that key.
const (
	fixturePassword = "correct-horse"
	// pbes2AES256SHA256 uses AES-256-CBC with PBKDF2 and hmacWithSHA256.
	pbes2AES256SHA256 = "3081f4305f06092a864886f70d01050d3052303106092a864886f70d01050c30240410c887802b878abb4ddf64" +
		"578365a0e5df02020800300c06082a864886f70d02090500301d060960864801650304012a041067d4ef2ad6f8633d9e5b3ca02b" +
		"9364b4048190fb5855891abf211f73a346bdf6b5d9cfd1873d7f122b84d8d9804bb3a38dea490bd01cd65700c6c2f538178254" +
		"e74a3352979917377263753e677f38eb1f35ceb5c4a9421418958ba3b7fdb3397b1f9243ecac7ab46dc7df777c8723937f05c5" +
		"8f8418a5e4f855387b5dd0a85ca31e065a830d6a9629cbc9ae79a82d97db382871a3c5deb9da088988d7e918f5fd07c1"
	// pbes2AES128SHA1 uses AES-128-CBC with PBKDF2 and the default hmacWithSHA1, which its
	// parameters leave out.
	pbes2AES128SHA1 = "3081e6305106092a864886f70d01050d3044302306092a864886f70d01050c30160410f38a7114d0187286d0c1" +
		"42bd62e92edc02020800301d060960864801650304010204105f93d013cc061b8d38d0ffafc168c84b0481908d0d898defffcd" +
		"018f450c18a26ec598777d18256c6fae65f21760452b06264864ee76446f368dfbce04d8a747b12007434a048398e340381804" +
		"63fa34f6939de5a0222b193975c4b90bec42da3ae82c710f548ff0a66446354e723b5c41f543bbc76313aa895b05ecf8e3ee4" +
		"62a9776e012512e48fed08015d20506fbeba6a757645faf948964305c937c902de92cd5"
	// pbes2DES3 uses DES-EDE3-CBC, which is not supported.
	pbes2DES3 = "3081eb305606092a864886f70d01050d3049303106092a864886f70d01050c302404104c0064703d0d496d5497f595" +
		"545e69e902020800300c06082a864886f70d02090500301406082a864886f70d030704081ab0979583225f90048190c4ffc0b9" +
		"1a494eb9313704ec48af2c217d8e4d1698d46dc67621d82d1b2dfd1be266b849b682ebcda27c69c069dae7e2315a23a04cea6" +
		"4540fef3db150cf4d0a114a6f878cc495021349dfad03dbaa30f724ec46491a92917d728151248ac1f78e4f20e69d82260d89" +
		"d3d4893b988c0ec58490ae84bc1e724ae8ff2978c113ba1ad414a26c27b3dded5a51f728f4616f"
	fixturePublicKey = "3059301306072a8648ce3d020106082a8648ce3d03010703420004071cfd327039d9d3b35614cfc74132d37e57" +
		"765aa1f78c64e11ed0ca00e424bcc3b01d01710048bdb8974415983737a5b7f7f0f890824a6c4a58c0e783a5637d"
)

// fromHex decodes a hex fixture.
func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestParseEncrypted checks the decryption of keys that openssl pkcs8 -topk8 wrote, as DER and PEM,
// and the errors for a wrong password, an unsupported cipher and input that is not encrypted.
func TestParseEncrypted(t *testing.T) {
	pub, err := x509.ParsePKIXPublicKey(fromHex(t, fixturePublicKey))
	if err != nil {
		t.Fatal(err)
	}
	password := []byte(fixturePassword)
	der := fromHex(t, pbes2AES256SHA256)
	for name, data := range map[string][]byte{
		"AES-256 SHA-256 DER": der,
		"AES-256 SHA-256 PEM": pem.EncodeToMemory(&pem.Block{Type: pemEncryptedPKCS8, Bytes: der}),
		"AES-128 SHA-1 DER":   fromHex(t, pbes2AES128SHA1),
	} {
		if _, err := Parse(data); !errors.Is(err, ErrEncrypted) {
			t.Errorf("%s: Parse error = %v, want ErrEncrypted", name, err)
		}
		key, err := ParseEncrypted(data, password)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(pub) {
			t.Errorf("%s: decrypted key differs", name)
		}
	}
	plainKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x509.MarshalPKCS8PrivateKey(plainKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		data, password []byte
		want           string
	}{
		"wrong password": {der, []byte("wrong-horse"), "wrong password"},
		"3DES":           {fromHex(t, pbes2DES3), password, "want AES"},
		"not encrypted":  {plain, password, "not an EncryptedPrivateKeyInfo"},
		"wrong block":    {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), password, "unexpected PEM block"},
	} {
		if _, err := ParseEncrypted(tt.data, tt.password); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tt.want)
		}
	}
}
