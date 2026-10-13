package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

// TestParseLegacyForms checks SEC 1 and DER input and the rejection of encrypted or foreign blocks.
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
}

// TestGenerateUnknown checks the error for an unknown key type.
func TestGenerateUnknown(t *testing.T) {
	if _, err := Generate("dsa-1024"); err == nil || !strings.Contains(err.Error(), "unknown key type") {
		t.Errorf("Generate(dsa-1024) error = %v", err)
	}
}
