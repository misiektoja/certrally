package cli

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Algorithm identifiers the request-shaping tests look for.
var (
	oidPasswordBasedMac = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
	oidSHA384           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidHMACWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidECDSAWithSHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// pbmParameter is the PBMParameter of RFC 4210 §5.1.3.1.
type pbmParameter struct {
	Salt           []byte
	OWF            pkix.AlgorithmIdentifier
	IterationCount int
	MAC            pkix.AlgorithmIdentifier
}

// firstMessage returns the first message of a capture file, the request that opened the exchange.
func firstMessage(t *testing.T, capture string) *pkicmp.PKIMessage {
	t.Helper()
	msg, err := pkicmp.ParsePKIMessage(readCapture(t, capture)[0].DER)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// certReqMsg returns the single certificate request of an ir, cr or kur.
func certReqMsg(t *testing.T, msg *pkicmp.PKIMessage) *pkicmp.CertReqMsg {
	t.Helper()
	var reqs *pkicmp.CertReqMessages
	var err error
	switch msg.Body.Type {
	case pkicmp.BodyTypeCR:
		reqs, err = msg.Body.CR()
	case pkicmp.BodyTypeKUR:
		reqs, err = msg.Body.KUR()
	default:
		reqs, err = msg.Body.IR()
	}
	if err != nil {
		t.Fatal(err)
	}
	if reqs == nil || len(*reqs) != 1 {
		t.Fatalf("the request holds %v certificate requests", reqs)
	}
	return &(*reqs)[0]
}

// TestEnrollRequestShape checks that --cert-req-id and --general-info shape the request as asked.
// The mock CA refuses a certReqId other than 0 unless told to accept it, as RFC 9483 asks.
func TestEnrollRequestShape(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	if code, errOut, _ := mockEnroll(t, m, "--cert-req-id", "1023"); code != exitRejected || !errorContains(errOut, "certReqId must be 0") {
		t.Errorf("enroll with certReqId 1023 exited with %d, want %d with the refusal:\n%s", code, exitRejected, errOut)
	}

	lenient := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--accept", "any-cert-req-id")
	code, errOut, capture := mockEnroll(t, lenient, "--cert-req-id", "1023", "--cert-profile", "device",
		"--general-info", "1.3.6.1.4.1.36878.3.3.1.1:int:7",
		"--general-info", "1.2.3.4:str:hello",
		"--general-info", "1.2.3.5:hex:0500")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	msg := firstMessage(t, capture)
	if got := certReqMsg(t, msg).CertReq.CertReqID; got != 1023 {
		t.Errorf("certReqId = %d, want 1023", got)
	}
	ip, err := pkicmp.ParsePKIMessage(readCapture(t, capture)[1].DER)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := ip.Body.IP(); err != nil || len(rep.Response) != 1 || rep.Response[0].CertReqID != 1023 {
		t.Errorf("the response does not repeat certReqId 1023: %v, %v", rep, err)
	}
	if got := msg.Header.CertProfile(); got != "device" {
		t.Errorf("certProfile = %q, want device", got)
	}
	want := []pkicmp.InfoTypeAndValue{
		{InfoType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 36878, 3, 3, 1, 1}, InfoValue: []byte{0x02, 0x01, 0x07}},
		{InfoType: asn1.ObjectIdentifier{1, 2, 3, 4}, InfoValue: []byte{0x0c, 0x05, 'h', 'e', 'l', 'l', 'o'}},
		{InfoType: asn1.ObjectIdentifier{1, 2, 3, 5}, InfoValue: []byte{0x05, 0x00}},
	}
	info := msg.Header.GeneralInfo
	if len(info) != len(want)+1 {
		t.Fatalf("the header carries %d generalInfo items, want %d", len(info), len(want)+1)
	}
	for i, w := range want {
		got := info[i+1]
		if !got.InfoType.Equal(w.InfoType) || !bytes.Equal(got.InfoValue, w.InfoValue) {
			t.Errorf("generalInfo[%d] = %v %x, want %v %x", i+1, got.InfoType, got.InfoValue, w.InfoType, w.InfoValue)
		}
	}
}

// TestEnrollHash checks that --hash and --iterations select the MAC, the proof of possession, the
// signature and the PKCS#10 signature.
func TestEnrollHash(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)

	t.Run("pbm", func(t *testing.T) {
		capture := filepath.Join(t.TempDir(), "capture.jsonl")
		enrollIR(t, ca, "--capture", capture, "--mac", "pbm", "--hash", "sha384", "--iterations", "777")
		msg := firstMessage(t, capture)
		if !msg.Header.ProtectionAlg.Algorithm.Equal(oidPasswordBasedMac) {
			t.Fatalf("protectionAlg = %v, want PasswordBasedMac", msg.Header.ProtectionAlg.Algorithm)
		}
		var params pbmParameter
		if _, err := asn1.Unmarshal(msg.Header.ProtectionAlg.Parameters, &params); err != nil {
			t.Fatal(err)
		}
		if !params.OWF.Algorithm.Equal(oidSHA384) || !params.MAC.Algorithm.Equal(oidHMACWithSHA384) || params.IterationCount != 777 {
			t.Errorf("PBM uses OWF %v, MAC %v and %d iterations, want SHA-384, HMAC-SHA384 and 777",
				params.OWF.Algorithm, params.MAC.Algorithm, params.IterationCount)
		}
		if alg := certReqMsg(t, msg).Popo.Signature.Algorithm.Algorithm; !alg.Equal(oidECDSAWithSHA384) {
			t.Errorf("proof of possession uses %v, want ecdsa-with-SHA384", alg)
		}
	})

	t.Run("signature", func(t *testing.T) {
		certOut, keyOut := enrollIR(t, ca)
		dir := t.TempDir()
		capture := filepath.Join(dir, "capture.jsonl")
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--type", "cr", "--cert", certOut, "--key", keyOut,
			"--subject", "CN=device-42", "--hash", "sha512", "--capture", capture,
			"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem"))
		if code != exitOK {
			t.Fatalf("exited with %d:\n%s", code, errOut)
		}
		msg := firstMessage(t, capture)
		if !msg.Header.ProtectionAlg.Algorithm.Equal(oidECDSAWithSHA512) {
			t.Errorf("protectionAlg = %v, want ecdsa-with-SHA512", msg.Header.ProtectionAlg.Algorithm)
		}
		if alg := certReqMsg(t, msg).Popo.Signature.Algorithm.Algorithm; !alg.Equal(oidECDSAWithSHA512) {
			t.Errorf("proof of possession uses %v, want ecdsa-with-SHA512", alg)
		}
	})

	t.Run("p10cr", func(t *testing.T) {
		capture := filepath.Join(t.TempDir(), "capture.jsonl")
		enrollIR(t, ca, "--capture", capture, "--type", "p10cr", "--mac", "pbm", "--hash", "sha384")
		csr, err := firstMessage(t, capture).Body.P10CR()
		if err != nil {
			t.Fatal(err)
		}
		if csr.SignatureAlgorithm != x509.ECDSAWithSHA384 {
			t.Errorf("the PKCS#10 request is signed with %v, want ECDSA-SHA384", csr.SignatureAlgorithm)
		}
	})
}

// TestEnrollRequestOptionUsage checks the usage errors of the request-shaping flags.
func TestEnrollRequestOptionUsage(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	edCert, edKey := enrollIR(t, ca, "--key-type", "ed25519")
	sent := ca.requests.Load()
	dir := t.TempDir()
	out, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	outputs := []string{"--cert-out", out, "--key-out", key}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"negative cert-req-id", []string{"--ref", testRef, "--cert-req-id", "-1"}, "--cert-req-id must not be negative"},
		{"cert-req-id with p10cr", []string{"--ref", testRef, "--type", "p10cr", "--cert-req-id", "5"}, "a p10cr request carries no certReqId"},
		{"bad hash", []string{"--ref", testRef, "--hash", "md5"}, "invalid --hash"},
		{"hash with pbmac1", []string{"--ref", testRef, "--hash", "sha256"}, "--mac pbm"},
		{"hash with ed25519 key", []string{"--ref", testRef, "--mac", "pbm", "--hash", "sha256", "--key-type", "ed25519"}, "not to the Ed25519 key to certify"},
		{"hash with ed25519 cert", []string{"--type", "cr", "--cert", edCert, "--key", edKey, "--hash", "sha256"}, "not to the Ed25519 key in " + edKey},
		{"negative iterations", []string{"--ref", testRef, "--iterations", "-1"}, "--iterations must be positive"},
		{"iterations with cert", []string{"--type", "cr", "--cert", edCert, "--key", edKey, "--iterations", "5"}, "--iterations sets the shared-secret MAC"},
		{"general-info format", []string{"--ref", testRef, "--general-info", "1.2.3"}, "want OID:int:N"},
		{"general-info OID", []string{"--ref", testRef, "--general-info", "9.9:int:1"}, `invalid OID "9.9"`},
		{"general-info int", []string{"--ref", testRef, "--general-info", "1.2.3:int:x"}, `"x" is not an integer`},
		{"general-info hex", []string{"--ref", testRef, "--general-info", "1.2.3:hex:zz"}, "--general-info"},
		{"general-info two values", []string{"--ref", testRef, "--general-info", "1.2.3:hex:05000500"}, "more than one value"},
		{"general-info type", []string{"--ref", testRef, "--general-info", "1.2.3:oid:1"}, "unknown value type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"enroll", "--server", ca.url}, append(tt.args, outputs...)...)
			code, _, errOut := run(t, args...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want 1 and %q in:\n%s", code, tt.want, errOut)
			}
		})
	}
	if n := ca.requests.Load(); n != sent {
		t.Errorf("the CA received %d requests", n-sent)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a failed enroll wrote %s: %v", out, err)
	}
}
