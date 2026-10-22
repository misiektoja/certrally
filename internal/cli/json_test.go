package cli

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
)

// runJSON runs a command line with --json and decodes the single document on standard output.
// Nothing may appear on standard error.
func runJSON(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	code, out, errOut := run(t, append(args, "--json")...)
	if errOut != "" {
		t.Errorf("standard error is not empty:\n%s", errOut)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("standard output is not JSON: %v\n%s", err, out)
	}
	if dec.More() {
		t.Fatalf("standard output holds more than one document:\n%s", out)
	}
	if doc["exitStatus"] != float64(code) || doc["ok"] != (code == exitOK) {
		t.Errorf("exitStatus %v and ok %v for exit status %d", doc["exitStatus"], doc["ok"], code)
	}
	return code, doc
}

// get returns the value at a dotted path such as "result.chain.0.subject", or nil.
func get(v any, path string) any {
	for key := range strings.SplitSeq(path, ".") {
		switch node := v.(type) {
		case map[string]any:
			v = node[key]
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(node) {
				return nil
			}
			v = node[i]
		default:
			return nil
		}
	}
	return v
}

// exchangeBodies lists the body of every message in the exchange.
func exchangeBodies(doc map[string]any) string {
	events, _ := doc["exchange"].([]any)
	bodies := make([]string, 0, len(events))
	for _, ev := range events {
		body, _ := get(ev, "body").(string)
		bodies = append(bodies, body)
	}
	return strings.Join(bodies, " ")
}

// parsePEMCertificate parses the single certificate in a PEM string.
func parsePEMCertificate(t *testing.T, v any) *x509.Certificate {
	t.Helper()
	s, _ := v.(string)
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatalf("not PEM: %v", v)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestEnrollJSON checks the document of a successful enrollment.
func TestEnrollJSON(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	code, doc := runJSON(t, "enroll", "--server", ca.url, "--ref", testRef, "--subject", "CN=device-42",
		"--san", "device-42.example.com", "--cert-out", certOut, "--key-out", keyOut)
	if code != exitOK {
		t.Fatalf("exited with %d: %v", code, doc)
	}
	if doc["command"] != "enroll" || doc["server"] != ca.url || doc["error"] != nil {
		t.Errorf("document = %v", doc)
	}
	if got := exchangeBodies(doc); got != "ir ip certConf pkiconf" {
		t.Errorf("exchange bodies = %q", got)
	}
	if get(doc, "exchange.0.der") != nil || get(doc, "exchange.1.status") != "accepted" || get(doc, "exchange.0.protection") != "PBMAC1" {
		t.Errorf("exchange = %v", doc["exchange"])
	}
	if get(doc, "result.status") != "accepted" || get(doc, "result.confirmed") != true {
		t.Errorf("result = %v", doc["result"])
	}
	cert := readCert(t, certOut)
	if !parsePEMCertificate(t, get(doc, "result.certificate.pem")).Equal(cert) {
		t.Error("result.certificate.pem is not the saved certificate")
	}
	if get(doc, "result.certificate.subject") != "CN=device-42" || get(doc, "result.certificate.altNames.0") != "device-42.example.com" {
		t.Errorf("certificate = %v", get(doc, "result.certificate"))
	}
	if get(doc, "result.certificate.serial") != strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())) {
		t.Errorf("serial = %v", get(doc, "result.certificate.serial"))
	}
	if get(doc, "result.chain.0.subject") != "CN=Test CA" || get(doc, "result.saved.1") != certOut {
		t.Errorf("chain and saved = %v %v", get(doc, "result.chain"), get(doc, "result.saved"))
	}
	if data, _ := json.Marshal(doc); strings.Contains(string(data), "PRIVATE KEY") {
		t.Error("the document contains a private key")
	}
}

// TestFailureJSON checks the error member and exit status of each failure class.
func TestFailureJSON(t *testing.T) {
	ca := startCA(t, nil)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	unconfirming := startCA(t, func(m *mockserver.MockCA) server.CA { return unconfirmingCA{m} })
	other := startCA(t, nil)

	tests := []struct {
		name     string
		secret   string
		server   string
		extra    []string
		wantCode int
		want     map[string]any
	}{
		{"rejected", "wrong", ca.url, nil, exitRejected, map[string]any{
			"error.title": "The CA rejected the request", "error.status": "rejection",
			"error.failInfo.0": "badMessageCheck", "error.unauthenticated": nil, "exchange.1.body": "error",
		}},
		{"rejected by another CA", "wrong", ca.url, []string{"--ca-cert", other.caFile}, exitRejected, map[string]any{
			"error.status": "rejection", "error.unauthenticated": true,
		}},
		{"transport", testSecret, closed.URL, nil, exitTransport, map[string]any{
			"error.title": "No CMP answer from the server", "error.hint": "Check the host and port in --server.",
			"exchange.1.kind": "failure",
		}},
		{"unconfirmed", testSecret, unconfirming.url, nil, exitUnconfirmed, map[string]any{
			"error.title": "The certificate was issued but the confirmation failed", "result.confirmed": false,
		}},
		{"local", testSecret, ca.url, []string{"--subject", "XX=1"}, exitLocal, map[string]any{
			"error.title": "The command failed", "command": "enroll",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useSecret(t, tt.secret)
			dir := t.TempDir()
			args := append([]string{"enroll", "--server", tt.server, "--ref", testRef,
				"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem")}, tt.extra...)
			code, doc := runJSON(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exited with %d, want %d: %v", code, tt.wantCode, doc)
			}
			for path, want := range tt.want {
				if got := get(doc, path); got != want {
					t.Errorf("%s = %v, want %v", path, got, want)
				}
			}
			if msg, _ := get(doc, "error.message").(string); msg == "" {
				t.Errorf("error.message is empty: %v", doc["error"])
			}
		})
	}
}

// TestUsageErrorJSON checks that a command line cobra rejects still gives a document, while the
// error is also printed for a person.
func TestUsageErrorJSON(t *testing.T) {
	isolateColorEnv(t)
	for _, args := range [][]string{
		{"enroll", "--no-such-flag", "--json"},
		{"ping", "--server", "http://ca.test", "--json", "--quiet"},
		{"enroll", "--json"},
	} {
		code, out, errOut := run(t, args...)
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%q: standard output is not JSON: %v\n%s", args, err, out)
		}
		if code != exitLocal || doc["exitStatus"] != float64(exitLocal) || get(doc, "error.title") != "Invalid command line" {
			t.Errorf("%q exited with %d: %v", args, code, doc)
		}
		if doc["command"] != args[0] || errOut == "" {
			t.Errorf("%q: command %v, standard error %q", args, doc["command"], errOut)
		}
	}
}

// TestCommandsJSON checks the result member of every command that talks to a server.
func TestCommandsJSON(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	other := startCA(t, nil)
	certFile, keyFile := enrollIR(t, ca, "--subject", "CN=device-42")
	crlFile := filepath.Join(t.TempDir(), "ca.crl")

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     map[string]any
	}{
		{"cacerts", []string{"cacerts"}, exitOK, map[string]any{"command": "cacerts", "result.certificates.0.subject": "CN=Test CA"}},
		{"genm cacerts", []string{"cmp", "genm", "cacerts"}, exitOK, map[string]any{"command": "cmp genm cacerts"}},
		{"rootupdate", []string{"cmp", "genm", "rootupdate", "--old-root", ca.caFile}, exitOK, map[string]any{"result.update": nil}},
		{"template", []string{"cmp", "genm", "template"}, exitOK, map[string]any{
			"result.template.subject": "CN=", "result.template.keyTypes.0": "ECDSA P-256",
		}},
		{"crl", []string{"cmp", "genm", "crl", "--out", crlFile}, exitOK, map[string]any{
			"result.crl.signature": "valid", "result.crl.revoked": float64(0), "result.crl.number": "1", "result.saved.0": crlFile,
		}},
		{"crlupdate", []string{"cmp", "genm", "crlupdate", "--crl", crlFile}, exitOK, map[string]any{"result.crl": nil}},
		{"raw", []string{"cmp", "genm", "raw", "caCerts"}, exitOK, map[string]any{
			"result.items.0.infoType": "caCerts", "result.items.0.oid": "1.3.6.1.5.5.7.4.17",
		}},
		{"revoke", []string{"revoke", "--cert", certFile, "--key", keyFile, "--reason", "superseded", "--yes"}, exitOK, map[string]any{
			"result.reason": "superseded", "result.certificate.subject": "CN=device-42", "exchange.1.body": "rp",
		}},
		{"ping", []string{"ping", "-c", "2", "-i", "0s"}, exitOK, map[string]any{
			"result.sent": float64(2), "result.answered": float64(2), "result.sender": "CN=Test CA", "result.verified": nil,
		}},
		{"ping pinned", []string{"ping", "--ca-cert", ca.caFile}, exitOK, map[string]any{"result.verified": true}},
		{"ping other CA", []string{"ping", "--ca-cert", other.caFile}, exitProtocol, map[string]any{
			"result.verified": false, "error.title": "The server answers CMP, but not as the CA in --ca-cert",
		}},
		{"stdout conflict", []string{"cacerts", "--out", "-"}, exitLocal, map[string]any{"exchange": nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(slices.Clone(tt.args), "--server", ca.url)
			if tt.args[0] != "ping" && tt.args[0] != "revoke" {
				args = append(args, "--ref", testRef)
			}
			code, doc := runJSON(t, args...)
			if code != tt.wantCode {
				t.Fatalf("exited with %d, want %d: %v", code, tt.wantCode, doc)
			}
			for path, want := range tt.want {
				if got := get(doc, path); got != want {
					t.Errorf("%s = %v, want %v", path, got, want)
				}
			}
		})
	}
}

// TestCMPGroupJSON checks that the CMP commands also run under cmp and report the command as typed.
func TestCMPGroupJSON(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	code, doc := runJSON(t, "cmp", "enroll", "--server", ca.url, "--ref", testRef,
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))
	if code != exitOK || get(doc, "command") != "cmp enroll" {
		t.Fatalf("cmp enroll exited with %d as %v: %v", code, get(doc, "command"), doc)
	}
	code, doc = runJSON(t, "cmp", "cacerts", "--server", ca.url, "--ref", testRef)
	if code != exitOK || get(doc, "command") != "cmp cacerts" {
		t.Errorf("cmp cacerts exited with %d as %v: %v", code, get(doc, "command"), doc)
	}
}

// TestKeygenJSON checks the keygen document, which must not contain the private key.
func TestKeygenJSON(t *testing.T) {
	isolateColorEnv(t)
	dir := t.TempDir()
	keyOut := filepath.Join(dir, "k.pem")
	code, doc := runJSON(t, "keygen", "--key-type", "ml-dsa-44", "--out", keyOut, "--csr-out", filepath.Join(dir, "r.csr"), "--subject", "CN=a")
	if code != exitOK {
		t.Fatalf("exited with %d: %v", code, doc)
	}
	if get(doc, "result.keyType") != "ml-dsa-44" || get(doc, "result.key") != "ML-DSA-44" || get(doc, "result.saved.0") != keyOut {
		t.Errorf("result = %v", doc["result"])
	}
	for _, path := range []string{"result.publicKey", "result.csr"} {
		if s, _ := get(doc, path).(string); !strings.HasPrefix(s, "-----BEGIN ") {
			t.Errorf("%s = %v", path, get(doc, path))
		}
	}
	if data, _ := json.Marshal(doc); strings.Contains(string(data), "PRIVATE KEY") || doc["exchange"] != nil {
		t.Errorf("document = %s", data)
	}

	code, doc = runJSON(t, "keygen", "--list")
	if types, _ := get(doc, "result.keyTypes").([]any); code != exitOK || len(types) < 10 {
		t.Errorf("keygen --list: %v", doc)
	}
	if code, _ = runJSON(t, "keygen", "--out", "-"); code != exitLocal {
		t.Errorf("--out - with --json exited with %d", code)
	}
}

// TestCapture checks that runs append start, message and end lines with the message bytes.
func TestCapture(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	capture := filepath.Join(t.TempDir(), "run.jsonl")
	enrollIR(t, ca, "--capture", capture, "-q")
	if code, _, errOut := run(t, "ping", "--server", ca.url, "--capture", capture, "-q"); code != exitOK {
		t.Fatalf("ping exited with %d:\n%s", code, errOut)
	}

	f, err := os.Open(capture)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	var kinds []string
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		kind, _ := line["kind"].(string)
		kinds = append(kinds, kind)
		switch kind {
		case "start":
			if line["tool"] != "certrally" || line["server"] != ca.url {
				t.Errorf("start line = %v", line)
			}
		case "request", "response":
			der, err := base64.StdEncoding.DecodeString(line["der"].(string))
			if err != nil {
				t.Fatal(err)
			}
			msg, err := pkicmp.ParsePKIMessage(der)
			if err != nil || msg.Body.Type.String() != line["body"] {
				t.Errorf("der does not hold the %v message: %v", line["body"], err)
			}
		}
	}
	want := "start request response request response end start request response end"
	if got := strings.Join(kinds, " "); got != want {
		t.Errorf("kinds = %q, want %q", got, want)
	}
	if info, err := os.Stat(capture); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("capture file mode: %v %v", info, err)
	}
}

// TestCaptureSameAsOutput checks that a capture file cannot also be an output.
func TestCaptureSameAsOutput(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	file := filepath.Join(t.TempDir(), "same.pem")
	for _, args := range [][]string{
		{"enroll", "--ref", testRef, "--cert-out", file, "--key-out", file + ".key", "--capture", file},
		{"cacerts", "--ref", testRef, "--out", file, "--capture", file},
	} {
		code, _, errOut := run(t, append(args, "--server", ca.url)...)
		if code != exitLocal || !errorContains(errOut, "for an output") {
			t.Errorf("%q exited with %d:\n%s", args, code, errOut)
		}
	}
	if n := ca.requests.Load(); n != 0 {
		t.Errorf("the CA received %d requests", n)
	}
}

// TestCaptureUnwritable checks that an unwritable capture file stops the command before it sends.
func TestCaptureUnwritable(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	code, _, errOut := run(t, "ping", "--server", ca.url, "--capture", filepath.Join(t.TempDir(), "missing", "run.jsonl"))
	if code != exitLocal || !errorContains(errOut, "--capture") || ca.requests.Load() != 0 {
		t.Errorf("exited with %d after %d requests:\n%s", code, ca.requests.Load(), errOut)
	}
}
