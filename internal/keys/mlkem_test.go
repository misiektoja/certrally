package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// fixtureMLKEMBoth is an ML-KEM-768 key that openssl genpkey of OpenSSL 4.1 wrote, in its default
// seed-priv form, which holds the seed and the expanded key. fixtureMLKEMPublicSHA256 is the SHA-256
// of the SubjectPublicKeyInfo that openssl pkey -pubout writes for it.
const (
	fixtureMLKEMBoth = "" +
		"308209be020100300b0609608648016503040402048209aa308209a604408a526a12120517c21af2cd86d2fda534b9d2b365" +
		"a7b8d12e23f54a24e8248d48cd43747259f5271160897d2155e790638cc9ee4f6ee0eb513ff2e906e5d7076304820960ff15" +
		"9a18c244a15ac896164f53189fbdf8290416876054371abcaeadf9727380bd1b7cb897d37089217807c301073910bcf01c97" +
		"7858c75aa0867040566b1237738f018ac60847ad45eb2535777cee2c16bc89048bd9b0db8a72c2a382e3067d36bc40f18417" +
		"5e570f0e551df05a2548b2b140fa24868a14b7541eb742088dea0300a508cd60c2cf69a7171736991055183477d953433360" +
		"bbeef932a109553c60bf72389eba4a774990ceb574a8ad3104a495087061a88bf85dd973c260f95b51b8af20acae2b965df6" +
		"47544ce156cf51046749b3728047c0677da725b166208b9df592775a5128717d850c395ca810352314b1f4ae02a0af3f6479" +
		"3da51a0a38617267a8612936cc58605f099c16f1c1b1c7cb89638dad7c8f99ca1136a77c31aa074ea27ef659bbc54bbe0b71" +
		"81f7bb3bc65bb4ab8b6db6311f84273910f03e1caa3a9d143a6e5a4c2578806bf9c4b71a3823315ff7c0b118169e9d3b9696" +
		"e68d0eb563515454a72258e74a0d2c2140c62371b57b36d031b92eac3c1c40a7af9aa9c518097473631a0a19b1c31510c1be" +
		"5c73728447929a158d22459a2ce45148b8103fe905f5712c21c0be6d753f87f5c79124b2ad7b76c213251a3c6c28c7896320" +
		"899b2b44b2973156f43268e71aaad58fc1e1b8bd5844e3f0c838c2b682f729c8294fe9b4575ee5ba5719ac12f02b49e791bf" +
		"9929be24a8de15075841408c440f9c9196cff124edaa09b636550028a15c7518b8f80bc62c25ca29775a974d7d9c1bd39b88" +
		"a946350f678c5920675132169d06479f15a46b9c082b54aca2f864f9dc65b022983e3cb8241a9aa529c24343080085a5a0d9" +
		"0958c0ad7360c493c82c4238b8a76856a3b43fafa9b592a4ade9b3409aa44cb547c35d2388ba936dacd34f0c5a0acd4aa623" +
		"83147c6a622a323698b45e43194238305cd7d33aee9b0e5eb8190ba30d6911c576a6c1dae88b842b375d565d0e5b493a0268" +
		"d340996b11224c53a2444ac56cd41ea110132c8017dd5403dc093deb238678c98d094c841c0a76eba05794a0522af7026fc4" +
		"c7881216d183ac316889da7301b7287c19a6485975a77d48aba601836f432ff45ba0982717247cc38db2adc0d117abe69688" +
		"296b1087acdda02938717b48c661b9200a0399ad1f147fee612807442cd0b796960ca4685a8d23cab64cb2333d2b151e745a" +
		"415bbf6e7b9a68e873994b1c1b6c40051c09c407024b88bc5ae70532ec3bd7dc3a8b623ac406a59bfac778726412b412d222" +
		"4090bc236f6740052c9866a33b657b4f24b6a9a5ba638c84cac3138835fb9f3e9957d777b0c71968bc5b15d379129f713de4" +
		"1670c4f16ae3f0725ab2814c60b8f369b4ace62bc2bb1d53b97dbb311cecfac5c0a55e9a0739d6a17a0fc7c035a422260a0e" +
		"f8e332fbbb172ec13392429756db9f1e6031eec98f73888710fb6c81d131ae53501fe34a92d52c424b2f171a98a8002c4376" +
		"6d108aa78275414a83b95e1b0fd9a553fc42b8b34b1189ca1303925b1c5a54d7233ee7c5610f550eaec595c3360043d07110" +
		"eb66d81772bc44506b83684782941336273406599105aaf24820b91b4812f1633ab59734c1a6274490b4aa221e95c06c5bbc" +
		"155b56dcea6be8961f78e2a9c203cff514088af3cb98a0be5648bfa893352855cf1d5820644311d3f032fc31247aa5a9ddf6" +
		"5cba565ae33820c716bd5473a09a7a24c39904b16974040c6d6a8111b94542e25385281234c4371e0dd1af3bb08e627c107d" +
		"0aa78542207d057a71032e02029c70d627bef06279b536c8ba31e20a89635657c8930e04e59ae20c2a0ff82622f89b2da7a4" +
		"98d4a71fc089b032b52310cdff889a5a04400e2303e05642f829836236aeeff96cb5fa1c4b0c493e5b57b5fb14e8c65c1c8a" +
		"8d989703781ca38923c85b22bf6b5a00aa33802cc044dca3be409a932939275e5c9a31c72456c026c5472e8f2a9b01e7a70a" +
		"daaca8bac3a0d31cb8f307b317a4ca10372c49235cb22e40176abfd67a84e925b22c628fe1709946cab03aa444097b211530" +
		"1125601bda4519e0bdacdc1d9a05ac68d7c0ed9122bf41037be3bc2fd4adf15c18cc0cabfe0c5d1df07898e2951f83cf8907" +
		"a13af991e9d403a8524b6984aef0f80abc8142359349fcdc3143377614e8c8910b0901b2be737516041724f5a5a8dbe40bfc" +
		"73043c9259ec813fd54c24551438b370bb24593d3ba8c74975a5bf5436a9d941c67678f6d901a88a107ceba35cbacce295c6" +
		"defa5b1ea309ee13b09235c44e89ad1756aa3064354c25a5b59896361a920fabce2c31073ea1c5631b6cfea4ce5e959144cc" +
		"2655f0abb75532b7b554d9211248620d3881bc2b4235c56992f7550a8e34206fec14b389445fb36db6577680178aef4ca840" +
		"d549cbf45e185a12f279385a66c3f08aa8eb44109fd1ca4135ba80c42d3101a7d291958ed759b067c0bbb4a768e0bf2ee974" +
		"2df508fa3702e551409a02c1e466c91a3ac7deca24adec4b9a507fed64cf458a5578b2b04ef01196e263e5eca950f451dac5" +
		"2993a8a5fab886d366a52fd617838858bf02589e5b90cc934b1ec62aa2195260ba1ec9d68bec877d0df7721e6237b537c790" +
		"c64a19e558afc92a0a12b87b783c972952d0d768b02a51365a3b0814bbef78c3263a5b8f2a4ba560cf39371bc788046e162a" +
		"18e7a5de8916624387b01a9c0d6680ca7189b8ca8c26d9094dc67d8895b65512935425577e42a8f598b807452aeda79e467b" +
		"81fc517ac447b989a7aec08b38ac5a50f7b8a5ab3431e4a0b29067584abc0afca51117403fecfaada7ca8d3fd8bf35379761" +
		"7caaafb9c9174b17af4371be481f9605cec4db099788063ad97b4a7228fab7267726c251b03c7ee6540613ae9b2539e2ea69" +
		"d1cccc2fe15527a80573d9ae15042a82b56dec4116ed2b77f7585200136ded4792dbf599bfdb3a3457240541cfdb9a175085" +
		"92d562b0bb3ac7b219a4b4fa36c9d166313c7895720813d5410e33a81d187ed6c311aa33adff3c06fd6c71dba929a1f49a42" +
		"a797cf3cbb4e903865e81379cb6abe6942aec7c2e8c4524e6b5270eb194c95bbd606a59c0ccace2a4586391d1625b32a6a94" +
		"e50a7c161492b84557127290cb369767810cac53a10e50bd5b8b7becb6223c73586dbc2cd92b99791c7d2f0acc0e83bd05e9" +
		"2b121bcf45723a9cd662a3d670e124a8c1ab6dbe638cd95262676b656e93b22b2cc949876b0aa9c05c45a37cba7c98c93b4e" +
		"2396acc55ab824380d83432e976004b1c91edea5bbf4925153950037ce84bfc6545bebb94c0b55ecf38cb34d65a4bdb6d9df" +
		"ec382f9f8d44eb298dbf66ed65d3b86ecd43747259f5271160897d2155e790638cc9ee4f6ee0eb513ff2e906e5d70763"
	fixtureMLKEMPublicSHA256 = "8524a303b81c0413e36d0385a829cc422957d2e12e3245ac90938b8b0528b86e"
)

// fixtureBoth returns the DER of fixtureMLKEMBoth.
func fixtureBoth(t *testing.T) []byte {
	t.Helper()
	der, err := hex.DecodeString(fixtureMLKEMBoth)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// requirePublic checks that the public key of key encodes to the SubjectPublicKeyInfo of the fixture.
func requirePublic(t *testing.T, key any) {
	t.Helper()
	der, err := MarshalPublicKey(Public(key))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != fixtureMLKEMPublicSHA256 {
		t.Error("the key does not encode to the public key that OpenSSL wrote")
	}
}

// encryptPKCS8 encrypts the PrivateKeyInfo plain with PBES2, PBKDF2 with HMAC-SHA-256 and
// AES-256-CBC, as openssl pkcs8 -topk8 -v2 aes-256-cbc does.
func encryptPKCS8(t *testing.T, plain, password []byte) []byte {
	t.Helper()
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(iv)
	key, err := pbkdf2.Key(sha256.New, string(password), salt, 2048, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	n := aes.BlockSize - len(plain)%aes.BlockSize
	data := append(slices.Clone(plain), bytes.Repeat([]byte{byte(n)}, n)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	raw := func(v any) asn1.RawValue {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.RawValue{FullBytes: der}
	}
	prf := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}, Parameters: asn1.NullRawValue}
	params := pbes2Params{
		KeyDerivation: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: raw(pbkdf2Params{Salt: salt, Iterations: 2048, PRF: prf})},
		Encryption:    pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, Parameters: raw(iv)},
	}
	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: raw(params)},
		Data:      data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestParseMLKEMOpenSSL checks that the form OpenSSL writes parses, that Marshal writes a seed form
// that parses back to the same key and that an encrypted ML-KEM key decrypts.
func TestParseMLKEMOpenSSL(t *testing.T) {
	both := fixtureBoth(t)
	for name, data := range map[string][]byte{
		"DER": both,
		"PEM": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: both}),
	} {
		key, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := key.(*mlkem.DecapsulationKey768); !ok {
			t.Fatalf("%s: parsed a %T", name, key)
		}
		requirePublic(t, key)
	}

	key, err := Parse(both)
	if err != nil {
		t.Fatal(err)
	}
	seedForm, err := Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	info, ok := readPKCS8(seedForm)
	if !ok || !info.algorithm.Equal(oidMLKEM768) || len(info.privateKey) != 2+mlkemSeedSize || info.privateKey[0] != 0x80 {
		t.Fatalf("Marshal did not write the seed form: % x", seedForm[:min(len(seedForm), 40)])
	}
	reparsed, err := Parse(seedForm)
	if err != nil {
		t.Fatal(err)
	}
	requirePublic(t, reparsed)

	password := []byte(fixturePassword)
	encrypted := encryptPKCS8(t, both, password)
	if _, err := Parse(encrypted); !errors.Is(err, ErrEncrypted) {
		t.Errorf("Parse of the encrypted key: error = %v, want ErrEncrypted", err)
	}
	decrypted, err := ParseEncrypted(encrypted, password)
	if err != nil {
		t.Fatal(err)
	}
	requirePublic(t, decrypted)
	if _, err := ParseEncrypted(encrypted, []byte("wrong-horse")); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Errorf("wrong password: error = %v", err)
	}
}

// mlkemPKCS8 encodes a PKCS#8 PrivateKeyInfo for the ML-KEM private key encoding privateKey. A
// non-nil publicKey makes it a version 2 OneAsymmetricKey that carries the public key.
func mlkemPKCS8(t *testing.T, oid asn1.ObjectIdentifier, params bool, privateKey, publicKey []byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if publicKey != nil {
			b.AddASN1Int64(1)
		} else {
			b.AddASN1Int64(0)
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			if params {
				b.AddASN1NULL()
			}
		})
		b.AddASN1OctetString(privateKey)
		if publicKey != nil {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddUint8(0)
				b.AddBytes(publicKey)
			})
		}
	})
	return b.BytesOrPanic()
}

// bothForm encodes the both form of RFC 9935 §6 from a seed and an expanded key.
func bothForm(seed, expanded []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(seed)
		b.AddASN1OctetString(expanded)
	})
	return b.BytesOrPanic()
}

// expandedForm encodes the expandedKey form of RFC 9935 §6, which holds no seed.
func expandedForm(expanded []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1OctetString(expanded)
	return b.BytesOrPanic()
}

// seedForm encodes the seed form of RFC 9935 §6.
func seedForm(seed []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(seed) })
	return b.BytesOrPanic()
}

// TestParseMLKEMInvalid checks the errors for ML-KEM private keys that do not fit together or that
// crypto/mlkem cannot use.
func TestParseMLKEMInvalid(t *testing.T) {
	info, ok := readPKCS8(fixtureBoth(t))
	if !ok {
		t.Fatal("the fixture is not a PrivateKeyInfo")
	}
	s := cryptobyte.String(info.privateKey)
	var both, seed, expanded cryptobyte.String
	if !s.ReadASN1(&both, cbasn1.SEQUENCE) || !both.ReadASN1(&seed, cbasn1.OCTET_STRING) ||
		!both.ReadASN1(&expanded, cbasn1.OCTET_STRING) {
		t.Fatal("the fixture does not hold the both form")
	}
	// The encapsulation key follows dk_PKE, which is 384 * 3 bytes for ML-KEM-768.
	otherEK := slices.Clone([]byte(expanded))
	otherEK[384*3] ^= 1
	otherZ := slices.Clone([]byte(expanded))
	otherZ[len(otherZ)-1] ^= 1
	other, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	for name, tt := range map[string]struct {
		der  []byte
		want string
	}{
		"expanded key of another key": {mlkemPKCS8(t, oidMLKEM768, false, bothForm(seed, otherEK), nil), "do not match"},
		"expanded key with another z": {mlkemPKCS8(t, oidMLKEM768, false, bothForm(seed, otherZ), nil), "do not match"},
		"short expanded key":          {mlkemPKCS8(t, oidMLKEM768, false, bothForm(seed, expanded[:100]), nil), "do not match"},
		"short seed":                  {mlkemPKCS8(t, oidMLKEM768, false, seedForm(seed[:32]), nil), "seed is 32 bytes"},
		"algorithm parameters":        {mlkemPKCS8(t, oidMLKEM768, true, seedForm(seed), nil), "no algorithm parameters"},
		"ML-KEM-512":                  {mlkemPKCS8(t, oidMLKEM512, false, seedForm(seed), nil), "ML-KEM-512"},
		"expanded key alone":          {mlkemPKCS8(t, oidMLKEM768, false, expandedForm(expanded), nil), "without its seed"},
		"public key of another key": {
			mlkemPKCS8(t, oidMLKEM768, false, seedForm(seed), other.EncapsulationKey().Bytes()),
			"public key in the ML-KEM-768 private key does not match",
		},
	} {
		if _, err := Parse(tt.der); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tt.want)
		}
	}

	// The password is right, so the ML-KEM error is reported rather than a wrong password.
	encrypted512 := encryptPKCS8(t, mlkemPKCS8(t, oidMLKEM512, false, seedForm(seed), nil), []byte(fixturePassword))
	if _, err := ParseEncrypted(encrypted512, []byte(fixturePassword)); !errors.Is(err, errMLKEM512) {
		t.Errorf("encrypted ML-KEM-512: error = %v", err)
	}

	matching := mlkemPKCS8(t, oidMLKEM768, false, seedForm(other.Bytes()), other.EncapsulationKey().Bytes())
	if _, err := Parse(matching); err != nil {
		t.Errorf("version 2 key with its public key: %v", err)
	}
}

// TestSigner checks that ML-KEM keys are refused where a key must sign and that the signing key
// types leave them out.
func TestSigner(t *testing.T) {
	key, err := Generate("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Signer(key); err == nil || err.Error() != "an ML-KEM-768 key cannot sign" {
		t.Errorf("Signer error = %v", err)
	}
	if _, err := GenerateSigner("ml-kem-1024"); err == nil || !strings.Contains(err.Error(), "ml-kem-1024 keys cannot sign") {
		t.Errorf("GenerateSigner error = %v", err)
	}
	if _, err := GenerateSigner("ed25519"); err != nil {
		t.Errorf("GenerateSigner(ed25519): %v", err)
	}
	signing := SigningTypeNames()
	for _, name := range TypeNames() {
		typ, err := LookupType(strings.ToUpper(name))
		if err != nil {
			t.Fatal(err)
		}
		if want := !strings.HasPrefix(name, "ml-kem-"); typ.Signs != want || slices.Contains(signing, name) != want {
			t.Errorf("%s: Signs = %v, in SigningTypeNames = %v, want %v", name, typ.Signs, slices.Contains(signing, name), want)
		}
	}
	if _, err := LookupType("ml-kem-512"); err == nil {
		t.Error("LookupType(ml-kem-512) succeeded")
	}
}

// TestCertificateKeyMLKEM checks that the ML-KEM key of a certificate, which crypto/x509 leaves nil,
// is decoded, and that ML-KEM-512 is refused.
func TestCertificateKeyMLKEM(t *testing.T) {
	key, err := Parse(fixtureBoth(t))
	if err != nil {
		t.Fatal(err)
	}
	spki, err := MarshalPublicKey(Public(key))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := CertificateKey(&x509.Certificate{RawSubjectPublicKeyInfo: spki})
	if err != nil {
		t.Fatal(err)
	}
	if got := Describe(pub); got != "ML-KEM-768" {
		t.Errorf("Describe = %q", got)
	}
	der, err := MarshalPublicKey(pub)
	if err != nil || !bytes.Equal(der, spki) {
		t.Errorf("public key round trip: %v", err)
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidMLKEM512) })
		b.AddASN1BitString(make([]byte, 800))
	})
	if _, err := CertificateKey(&x509.Certificate{RawSubjectPublicKeyInfo: b.BytesOrPanic()}); !errors.Is(err, errMLKEM512) {
		t.Errorf("ML-KEM-512 certificate: error = %v", err)
	}
}
