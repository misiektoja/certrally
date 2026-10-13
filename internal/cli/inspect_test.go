package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"

	"github.com/misiektoja/certrally/internal/cmpfile"
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
		"0.protection.check":               "unchecked",
		"0.protection.problem":             "it needs the shared secret",
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
		"MAC        not checked, it needs the shared secret",
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
