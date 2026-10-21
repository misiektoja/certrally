package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/cmpfile"
	"github.com/misiektoja/certrally/internal/pemfile"
)

// recordCapture enrolls, updates and revokes a certificate and asks for a request template,
// recording the runs in a capture file. It returns the capture and the enrolled certificate.
func recordCapture(t *testing.T, ca *testCA) (capture, certFile string) {
	t.Helper()
	dir := t.TempDir()
	capture = filepath.Join(dir, "run.jsonl")
	certFile, keyFile := enrollIR(t, ca, "--capture", capture, "-q")
	kurCert, kurKey := filepath.Join(dir, "kur.pem"), filepath.Join(dir, "kur.key")
	for _, args := range [][]string{
		{"enroll", "--type", "kur", "--cert", certFile, "--key", keyFile, "--cert-out", kurCert, "--key-out", kurKey},
		{"revoke", "--cert", kurCert, "--key", kurKey, "--yes"},
		{"cmp", "genm", "template", "--ref", testRef},
	} {
		if code, _, errOut := run(t, append(args, "--server", ca.url, "--capture", capture, "-q")...); code != exitOK {
			t.Fatalf("%s exited with %d:\n%s", args[0], code, errOut)
		}
	}
	return capture, certFile
}

// readCapture returns the messages in a capture file.
func readCapture(t *testing.T, capture string) []cmpfile.Message {
	t.Helper()
	msgs, err := cmpfile.Read(capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	return msgs
}

// messageBodies lists the body and direction of every message in an inspect result.
func messageBodies(doc map[string]any) string {
	msgs, _ := get(doc, "result.messages").([]any)
	bodies := make([]string, 0, len(msgs))
	for _, m := range msgs {
		body, _ := get(m, "body").(string)
		if get(m, "direction") == "request" {
			body = "→" + body
		}
		bodies = append(bodies, body)
	}
	return strings.Join(bodies, " ")
}

// TestInspectCapture checks the description of every message of a capture.
func TestInspectCapture(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	capture, certFile := recordCapture(t, ca)
	caCert, enrolled := readCert(t, ca.caFile), readCert(t, certFile)

	code, doc := runJSON(t, "inspect", capture, "--ca-cert", ca.caFile)
	if code != exitOK {
		t.Fatalf("exited with %d: %v", code, doc)
	}
	want := "→ir ip →certConf pkiconf →kur kup →certConf pkiconf →rr rp →genm genp"
	if got := messageBodies(doc); got != want {
		t.Errorf("bodies = %q, want %q", got, want)
	}
	checks := map[string]any{
		"0.source":                         capture + ":2",
		"0.header.sender":                  "CN=" + testRef,
		"0.header.senderKid":               "6d792d646576696365",
		"0.protection.algorithm":           "PBMAC1",
		"0.protection.check":               "valid",
		"0.protection.problem":             nil,
		"0.requests.0.certReqId":           float64(0),
		"0.requests.0.subject":             "CN=" + testRef,
		"0.requests.0.key":                 "ECDSA P-256",
		"0.requests.0.pop":                 "signature",
		"0.requests.0.popSignature":        "valid",
		"1.responses.0.status":             "accepted",
		"1.responses.0.certificate.sha256": certificateResult(enrolled).SHA256,
		"1.extraCerts.0.subject":           caCert.Subject.String(),
		"2.confirmations.0.certReqId":      float64(0),
		"4.protection.check":               "valid",
		"4.protection.signer":              "CN=" + testRef,
		"4.protection.trusted":             true,
		"4.requests.0.oldCert.serial":      certificateResult(enrolled).Serial,
		"5.protection.signer":              caCert.Subject.String(),
		"8.revocations.0.reason":           "unspecified",
		"9.revocations.0.status":           "accepted",
		"10.items.0.infoType":              "certReqTemplate",
		"11.items.0.oid":                   "1.3.6.1.5.5.7.4.19",
	}
	for path, want := range checks {
		if got := get(doc, "result.messages."+path); got != want {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}

	code, out, errOut := run(t, "inspect", capture)
	for _, want := range []string{
		"→ ir  " + capture + ":2  PBMAC1",
		"← kup",
		"MAC        valid",
		"Signature  valid",
		"Extra certificate 1 (signer)",
		"Revocation request 1",
		"Sender KID      6D:79:2D:64:65:76:69:63:65 \"my-device\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if code != exitOK || errOut != "" || strings.Contains(out, "Trust") {
		t.Errorf("exited with %d:\n%s%s", code, errOut, out)
	}
}

// TestInspectProtection checks the signature and trust outcomes.
func TestInspectProtection(t *testing.T) {
	useSecret(t, testSecret)
	ca, other := startCA(t, nil), startCA(t, nil)
	capture, _ := recordCapture(t, ca)
	// The kup is signed by the CA, which puts its certificate in extraCerts.
	kup := readCapture(t, capture)[5]
	dir := t.TempDir()
	write := func(name string, der []byte) string {
		path := filepath.Join(dir, name)
		writeFile(t, path, der)
		return path
	}
	// The parsed message shares its bytes with the DER it came from.
	tampered, err := pkicmp.ParsePKIMessage(bytes.Clone(kup.DER))
	if err != nil {
		t.Fatal(err)
	}
	tampered.Protection[len(tampered.Protection)-1] ^= 0xff
	tamperedDER, err := tampered.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	kupFile, bare := write("kup.der", kup.DER), write("bare.der", withoutExtraCerts(kup.DER))

	tests := []struct {
		name    string
		args    []string
		check   string
		trusted any
		problem string
	}{
		{"trusted", []string{kupFile, "--ca-cert", ca.caFile}, "valid", true, ""},
		{"other CA", []string{kupFile, "--ca-cert", other.caFile}, "valid", false, ""},
		{"no --ca-cert", []string{kupFile}, "valid", nil, ""},
		{"tampered", []string{write("tampered.der", tamperedDER)}, "invalid", nil, "no certificate in extraCerts or --ca-cert verifies it"},
		{"no certificate", []string{bare}, "unchecked", nil, "the message carries no certificate and --ca-cert names none"},
		{"signer from --ca-cert", []string{bare, "--ca-cert", ca.caFile}, "valid", true, ""},
		{"signer not in --ca-cert", []string{bare, "--ca-cert", other.caFile}, "unchecked", nil, "no certificate in extraCerts or --ca-cert matches senderKID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, doc := runJSON(t, append([]string{"inspect"}, tt.args...)...)
			p := "result.messages.0.protection."
			if code != exitOK || get(doc, p+"check") != tt.check || get(doc, p+"trusted") != tt.trusted ||
				get(doc, p+"problem") != nil && get(doc, p+"problem") != tt.problem {
				t.Errorf("exited with %d: %v", code, get(doc, "result.messages.0.protection"))
			}
		})
	}
}

// TestInspectExpiredSigner checks a message whose signer expired after the capture recorded it. The signature
// verifies either way. The chain is checked at the capture time, or at the current time for a message file.
func TestInspectExpiredSigner(t *testing.T) {
	now := time.Now()
	caKey, caCert := testCertificate(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Old CA"},
		NotBefore:             now.Add(-4 * time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil)
	signerKey, signer := testCertificate(t, &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Old signer"},
		NotBefore:    now.Add(-3 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		SubjectKeyId: []byte{1, 2, 3},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, caCert, caKey)
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(signer.RawSubject),
	})
	creds, err := pkicmp.NewSignatureCredentials(signerKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.Protect(msg); err != nil {
		t.Fatal(err)
	}
	der, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caFile, derFile, capture := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "pkiconf.der"), filepath.Join(dir, "run.jsonl")
	writeFile(t, caFile, pemfile.EncodeCertificates([]*x509.Certificate{caCert}))
	writeFile(t, derFile, der)
	recorded := now.Add(-2 * time.Hour)
	var lines []byte
	for _, line := range []map[string]any{
		{"kind": "start", "format": 1, "server": "http://ca.example/cmp", "time": recorded},
		{"kind": "response", "time": recorded, "body": "pkiconf", "der": der},
	} {
		b, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(append(lines, b...), '\n')
	}
	writeFile(t, capture, lines)

	for file, trusted := range map[string]bool{capture: true, derFile: false} {
		code, doc := runJSON(t, "inspect", file, "--ca-cert", caFile)
		p := "result.messages.0.protection."
		if code != exitOK || get(doc, p+"check") != "valid" || get(doc, p+"signer") != "CN=Old signer" ||
			get(doc, p+"trusted") != trusted {
			t.Errorf("%s: exited with %d, want a valid signature and trusted %v: %v",
				filepath.Base(file), code, trusted, get(doc, "result.messages.0.protection"))
		}
	}
}

// TestInspectDamagedSignatureWithChain checks a damaged signature in a message that carries its CA certificate
// and no senderKID, as Nokia NCM sends them. The CA certificate does not name the sender, which must not turn
// the invalid signature into an unchecked one.
func TestInspectDamagedSignatureWithChain(t *testing.T) {
	now := time.Now()
	caKey, caCert := testCertificate(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Chain CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil)
	signerKey, signer := testCertificate(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Chain signer"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}, caCert, caKey)
	msg := pkicmp.NewPKIMessage(pkicmp.NewPKIConfBody(), pkicmp.MessageOptions{
		Sender: pkicmp.NewDirectoryNameFromRawDER(signer.RawSubject),
	})
	creds, err := pkicmp.NewSignatureCredentials(signerKey, signer, caCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.Protect(msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.Header.SenderKID) != 0 || len(msg.ExtraCerts) != 2 {
		t.Fatalf("senderKID %X and %d extra certificates, want none and 2", msg.Header.SenderKID, len(msg.ExtraCerts))
	}
	msg.Protection[len(msg.Protection)/2] ^= 0xff
	der, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "damaged.der")
	writeFile(t, file, der)

	code, doc := runJSON(t, "inspect", file)
	if p := "result.messages.0.protection."; code != exitOK || get(doc, p+"check") != "invalid" {
		t.Errorf("exited with %d, want an invalid signature: %v", code, get(doc, "result.messages.0.protection"))
	}
}

// testCertificate certifies a new key with template, signed by issuerKey under issuer or self-signed when
// issuer is nil.
func testCertificate(t *testing.T, template, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	if issuer == nil {
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// TestInspectMAC checks MACs with the shared secret from --secret-file and from the environment.
func TestInspectMAC(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	capture := filepath.Join(dir, "run.jsonl")
	enrollIR(t, ca, "--capture", capture, "-q")
	enrollIR(t, ca, "--mac", "pbm", "--capture", capture, "-q")
	secretFile, wrongFile := filepath.Join(dir, "secret.txt"), filepath.Join(dir, "wrong.txt")
	writeFile(t, secretFile, []byte(testSecret+"\n"))
	writeFile(t, wrongFile, []byte("wrong"))
	// A sender may choose more iterations than go-pki-cmp computes by default.
	slow := filepath.Join(dir, "slow.der")
	iterations := pkicmp.DefaultMaxMACIterationCount + 1
	writeFile(t, slow, protectWithMAC(t, readCapture(t, capture)[0].DER, pkicmp.WithPBM(),
		pkicmp.WithMACIterationCount(iterations), pkicmp.WithMACIterationLimits(1, iterations)))

	tests := []struct {
		name    string
		env     string
		args    []string
		check   string
		problem string
	}{
		{"environment", testSecret, []string{capture}, "valid", ""},
		{"--secret-file", "", []string{capture, "--secret-file", secretFile}, "valid", ""},
		{"--secret-file before environment", testSecret, []string{capture, "--secret-file", wrongFile}, "invalid", "it does not match the shared secret from --secret-file"},
		{"wrong secret in environment", "wrong", []string{capture}, "invalid", "it does not match the shared secret from CERTRALLY_SECRET"},
		{"no secret", "", []string{capture}, "unchecked", "it needs the shared secret from --secret-file or CERTRALLY_SECRET"},
		{"too many iterations", "", []string{slow, "--secret-file", secretFile}, "unchecked", "too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useSecret(t, tt.env)
			code, doc := runJSON(t, append([]string{"inspect"}, tt.args...)...)
			if code != exitOK {
				t.Fatalf("exited with %d: %v", code, doc)
			}
			msgs, _ := get(doc, "result.messages").([]any)
			algorithms := map[any]bool{}
			for i, m := range msgs {
				alg := get(m, "protection.algorithm")
				if alg != "PBM" && alg != "PBMAC1" {
					continue
				}
				algorithms[alg] = true
				problem, _ := get(m, "protection.problem").(string)
				if get(m, "protection.check") != tt.check || !strings.Contains(problem, tt.problem) || tt.problem == "" && problem != "" {
					t.Errorf("message %d: %v", i, get(m, "protection"))
				}
			}
			if len(algorithms) == 0 || len(tt.args) > 0 && tt.args[0] == capture && len(algorithms) != 2 {
				t.Errorf("MAC algorithms checked: %v", algorithms)
			}
		})
	}
}

// protectWithMAC returns der protected anew with the test secret and the MAC options.
func protectWithMAC(t *testing.T, der []byte, opts ...pkicmp.MACCredentialOption) []byte {
	t.Helper()
	msg, err := pkicmp.ParsePKIMessage(bytes.Clone(der))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := pkicmp.NewMACCredentials([]byte(testSecret), opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.Protect(msg); err != nil {
		t.Fatal(err)
	}
	out, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestInspectProofByDecryption checks the challenges of a popdecc body and the answers of a
// popdecr body, and that a popdecr file counts as a request.
func TestInspectProofByDecryption(t *testing.T) {
	useSecret(t, "")
	dir := t.TempDir()
	owf := &pkicmp.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
	challenges := pkicmp.POPODecKeyChallContent{
		{OWF: owf, Witness: []byte{0xab, 0xcd}, EncryptedRand: derSequence(38)},
		{Witness: []byte{0x01}, EncryptedRand: derSequence(5)},
	}
	answers := pkicmp.POPODecKeyRespContent{big.NewInt(0x1234), big.NewInt(5)}
	challFile, answerFile := filepath.Join(dir, "popdecc.der"), filepath.Join(dir, "popdecr.der")
	for file, body := range map[string]*pkicmp.PKIBody{challFile: pkicmp.NewPopDecCBody(&challenges), answerFile: pkicmp.NewPopDecRBody(&answers)} {
		der, err := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, file, der)
	}

	code, doc := runJSON(t, "inspect", challFile, answerFile)
	if code != exitOK {
		t.Fatalf("exited with %d: %v", code, doc)
	}
	msgs, _ := get(doc, "result.messages").([]any)
	if len(msgs) != 2 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if got := get(msgs[0], "direction"); got != "response" {
		t.Errorf("popdecc direction = %v", got)
	}
	if got := get(msgs[1], "direction"); got != "request" {
		t.Errorf("popdecr direction = %v", got)
	}
	for i, m := range msgs {
		if p := get(m, "problems"); p != nil {
			t.Errorf("message %d problems: %v", i, p)
		}
	}
	gotChallenges, _ := json.Marshal(get(msgs[0], "challenges"))
	wantChallenges := `[{"encryptedRandSize":40,"owf":"2.16.840.1.101.3.4.2.1","witness":"abcd"},{"encryptedRandSize":7,"witness":"01"}]`
	if string(gotChallenges) != wantChallenges {
		t.Errorf("challenges = %s, want %s", gotChallenges, wantChallenges)
	}
	if got := fmt.Sprint(get(msgs[1], "answers")); got != "[1234 05]" {
		t.Errorf("answers = %s", got)
	}

	code, out, errOut := run(t, "inspect", "--color", "never", challFile, answerFile)
	if code != exitOK {
		t.Fatalf("exited with %d:\n%s", code, errOut)
	}
	for _, want := range []string{"Challenge 1", "One-way function", "2.16.840.1.101.3.4.2.1", "AB:CD", "40 bytes", "Challenge 2", "Answer to challenge 1", "12:34", "Answer to challenge 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q:\n%s", want, out)
		}
	}
}

// derSequence returns a DER SEQUENCE with n zero content bytes, which stands in for EnvelopedData.
func derSequence(n int) []byte {
	return append([]byte{0x30, byte(n)}, make([]byte, n)...)
}

// TestInspectSecretFromStdin checks that --secret-file - reads the secret from standard input.
func TestInspectSecretFromStdin(t *testing.T) {
	useSecret(t, "other")
	var a anchors
	err := a.readSecret("-", strings.NewReader(testSecret+"\n"))
	if err != nil || string(a.secret) != testSecret || a.secretSource != "--secret-file" {
		t.Errorf("readSecret = %q from %q, %v", a.secret, a.secretSource, err)
	}
}

// TestInspectErrors checks files that cannot be inspected.
func TestInspectErrors(t *testing.T) {
	useSecret(t, "")
	ca := startCA(t, nil)
	dir := t.TempDir()
	jsonOutput := filepath.Join(dir, "out.json")
	writeFile(t, jsonOutput, []byte("{\n  \"command\": \"enroll\"\n}\n"))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing file", []string{filepath.Join(dir, "missing.der")}, "no such file"},
		{"stdin twice", []string{"-", "-"}, "- can appear only once"},
		{"json output", []string{jsonOutput}, "record the run with --capture"},
		{"certificate", []string{ca.caFile}, "not a CMP message"},
		{"missing --ca-cert", []string{jsonOutput, "--ca-cert", filepath.Join(dir, "missing.pem")}, "no such file"},
		{"missing --secret-file", []string{jsonOutput, "--secret-file", filepath.Join(dir, "missing.txt")}, "no such file"},
		{"stdin for file and secret", []string{"-", "--secret-file", "-"}, "cannot both be -"},
		{"no file", nil, "requires at least 1 arg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, append([]string{"inspect"}, tt.args...)...)
			if code != exitLocal || !strings.Contains(errOut, tt.want) {
				t.Errorf("exited with %d:\n%s", code, errOut)
			}
		})
	}
}
