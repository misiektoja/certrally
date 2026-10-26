package cli

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/misiektoja/certrally/internal/capture"
)

// reportedTransactionID finds the transaction ID in the text report of enroll.
var reportedTransactionID = regexp.MustCompile(`Transaction ID\s+([0-9a-f]+)`)

// transactionIDIn returns the transaction ID that the text report errOut shows.
func transactionIDIn(t *testing.T, errOut string) string {
	t.Helper()
	match := reportedTransactionID.FindStringSubmatch(errOut)
	if match == nil {
		t.Fatalf("the report shows no transaction ID:\n%s", errOut)
	}
	return match[1]
}

// lastTransactionState returns the state that the capture file records last for id.
func lastTransactionState(t *testing.T, path, id string) string {
	t.Helper()
	tr, err := capture.FindTransaction(path, id)
	if err != nil {
		t.Fatal(err)
	}
	return tr.State
}

// TestPollLater checks that enroll --poll-later stops at the waiting answer with the key saved and
// that poll, run in another directory, collects and confirms the certificate once.
func TestPollLater(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "2", "--check-after", "0s")
	dir := t.TempDir()
	t.Chdir(dir)
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=later",
		"--cert-out", "cert.pem", "--key-out", "key.pem", "--chain-out", "chain.pem", "--poll-later", "--capture", "run.jsonl")
	if code != exitOK || !strings.Contains(out, "Request waiting for the CA") {
		t.Fatalf("enroll exited with %d:\n%s%s", code, out, errOut)
	}
	id := transactionIDIn(t, out)
	if !strings.Contains(removeSpace(out), removeSpace("poll --transaction-id "+id+" --capture run.jsonl")) {
		t.Errorf("the report does not tell how to poll:\n%s", out)
	}
	if _, err := os.Stat("key.pem"); err != nil {
		t.Errorf("the key was not saved: %v", err)
	}
	if _, err := os.Stat("cert.pem"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a certificate file exists before poll: %v", err)
	}
	if n := strings.Count(m.stdout.String(), "pollReq"); n != 0 {
		t.Errorf("enroll sent %d polls, want none:\n%s", n, m.stdout)
	}

	t.Chdir(t.TempDir())
	captureFile := filepath.Join(dir, "run.jsonl")
	code, out, errOut = run(t, "poll", "--transaction-id", strings.ToUpper(id), "--capture", captureFile)
	if code != exitOK || !strings.Contains(out, "Certificate issued") || !strings.Contains(out, id) {
		t.Fatalf("poll exited with %d:\n%s%s", code, out, errOut)
	}
	cert := readCert(t, filepath.Join(dir, "cert.pem"))
	if cert.Subject.String() != "CN=later" {
		t.Errorf("subject = %q, want CN=later", cert.Subject)
	}
	if _, err := os.Stat(filepath.Join(dir, "chain.pem")); err != nil {
		t.Errorf("the chain was not saved: %v", err)
	}
	if n := strings.Count(m.stdout.String(), "pollReq"); n != 2 {
		t.Errorf("poll sent %d polls, want 2:\n%s", n, m.stdout)
	}
	if !strings.Contains(m.stdout.String(), "certConf") {
		t.Errorf("poll did not confirm the certificate:\n%s", m.stdout)
	}
	if got := lastTransactionState(t, captureFile, id); got != capture.TransactionEnded {
		t.Errorf("the capture file records the transaction as %q, want ended", got)
	}

	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitLocal || !errorContains(errOut, "already ended") {
		t.Errorf("a second poll exited with %d, want %d with the transaction ended:\n%s", code, exitLocal, errOut)
	}
}

// TestPollLaterJSON checks the documents of enroll --poll-later and poll.
func TestPollLaterJSON(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	dir := t.TempDir()
	captureFile := filepath.Join(dir, "run.jsonl")
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, doc := runJSON(t, "enroll", "--server", m.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut,
		"--poll-later", "--capture", captureFile)
	id, _ := get(doc, "exchange.0.transactionId").(string)
	if code != exitOK || id == "" || exchangeBodies(doc) != "ir ip" {
		t.Fatalf("enroll exited with %d:\n%v", code, doc)
	}
	for path, want := range map[string]any{
		"result.status":        "waiting",
		"result.confirmed":     false,
		"result.transactionId": id,
		"result.saved.0":       keyOut,
	} {
		if got := get(doc, path); got != want {
			t.Errorf("enroll %s = %v, want %v", path, got, want)
		}
	}
	if result, _ := doc["result"].(map[string]any); result["certificate"] != nil || len(result["chain"].([]any)) != 0 {
		t.Errorf("a waiting result holds a certificate: %v", result)
	}

	code, doc = runJSON(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitOK || doc["command"] != "poll" || exchangeBodies(doc) != "pollReq ip certConf pkiconf" {
		t.Fatalf("poll exited with %d:\n%v", code, doc)
	}
	for path, want := range map[string]any{
		"result.status":        "accepted",
		"result.confirmed":     true,
		"result.transactionId": id,
		"result.saved.0":       certOut,
	} {
		if got := get(doc, path); got != want {
			t.Errorf("poll %s = %v, want %v", path, got, want)
		}
	}
	parsePEMCertificate(t, get(doc, "result.certificate.pem"))
}

// TestPollLaterIssuedAtOnce checks that enroll --poll-later saves a certificate the CA issues at once
// and that poll then refuses the transaction because it never waited.
func TestPollLaterIssuedAtOnce(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef)
	dir := t.TempDir()
	captureFile := filepath.Join(dir, "run.jsonl")
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, doc := runJSON(t, "enroll", "--server", m.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut,
		"--poll-later", "--capture", captureFile)
	id, _ := get(doc, "result.transactionId").(string)
	if code != exitOK || get(doc, "result.status") != "accepted" || id == "" {
		t.Fatalf("enroll exited with %d:\n%v", code, doc)
	}
	readCert(t, certOut)

	code, _, errOut := run(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitLocal || !errorContains(errOut, "did not wait for the CA") {
		t.Errorf("poll exited with %d, want %d with the transaction not waiting:\n%s", code, exitLocal, errOut)
	}
	if n := strings.Count(m.stdout.String(), "pollReq"); n != 0 {
		t.Errorf("poll sent %d polls, want none:\n%s", n, m.stdout)
	}
}

// TestEnrollTimeoutThenPoll checks that an enroll whose polling ends at --timeout records the
// transaction, that a poll that ends the same way records it again and that a later poll succeeds.
func TestEnrollTimeoutThenPoll(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "2", "--check-after", "2s")
	dir := t.TempDir()
	captureFile := filepath.Join(dir, "run.jsonl")
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, _, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--cert-out", certOut, "--key-out", keyOut,
		"--capture", captureFile, "--timeout", "500ms")
	if code != exitTransport || !strings.Contains(errOut, "The CA has not decided yet") {
		t.Fatalf("enroll exited with %d, want %d:\n%s", code, exitTransport, errOut)
	}
	if !strings.Contains(removeSpace(errOut), removeSpace("poll --transaction-id")) {
		t.Errorf("the report does not tell how to poll:\n%s", errOut)
	}
	if _, err := os.Stat(keyOut); err != nil {
		t.Errorf("the key was not saved: %v", err)
	}
	id := strings.TrimPrefix(regexp.MustCompile(`--transaction-id [0-9a-f]+`).FindString(errOut), "--transaction-id ")

	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile, "--timeout", "200ms")
	if code != exitTransport || !strings.Contains(errOut, "Run the same poll command again later") {
		t.Fatalf("an early poll exited with %d, want %d:\n%s", code, exitTransport, errOut)
	}
	if got := lastTransactionState(t, captureFile, id); got != capture.TransactionWaiting {
		t.Errorf("the capture file records the transaction as %q, want waiting", got)
	}

	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("poll exited with %d:\n%s", code, errOut)
	}
	readCert(t, certOut)
	if n := strings.Count(m.stdout.String(), "pollReq"); n != 2 {
		t.Errorf("the mock answered %d polls, want 2:\n%s", n, m.stdout)
	}
}

// TestPollSigned checks that poll resumes a signature-protected request with the certificate and
// key of the enroll run and the trust it gained.
func TestPollSigned(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "device.pem"), filepath.Join(dir, "device.key")
	code, _, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--subject", "CN=device-42",
		"--cert-out", certFile, "--key-out", keyFile)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	useSecret(t, "")
	captureFile := filepath.Join(dir, "run.jsonl")
	certOut := filepath.Join(dir, "second.pem")
	code, out, errOut := run(t, "enroll", "--server", m.url, "--cert", certFile, "--key", keyFile, "--type", "cr",
		"--subject", "CN=second", "--cert-out", certOut, "--key-out", filepath.Join(dir, "second.key"),
		"--poll-later", "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("enroll --poll-later exited with %d:\n%s", code, errOut)
	}
	code, _, errOut = run(t, "poll", "--transaction-id", transactionIDIn(t, out), "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("poll exited with %d:\n%s", code, errOut)
	}
	if got := readCert(t, certOut).Subject.String(); got != "CN=second" {
		t.Errorf("subject = %q, want CN=second", got)
	}
}

// TestPollFailures checks that a poll that fails before the CA decides keeps the transaction, so the
// same command can run again, and that a rejection by the CA ends it.
func TestPollFailures(t *testing.T) {
	useSecret(t, testSecret)
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--waiting", "1", "--check-after", "0s")
	dir := t.TempDir()
	captureFile := filepath.Join(dir, "run.jsonl")
	certOut := filepath.Join(dir, "cert.pem")
	code, out, errOut := run(t, "enroll", "--server", m.url, "--ref", testRef, "--cert-out", certOut,
		"--key-out", filepath.Join(dir, "key.pem"), "--poll-later", "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	id := transactionIDIn(t, out)
	useSecret(t, "wrong-secret")
	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code == exitOK || !strings.Contains(errOut, "The transaction stays recorded") {
		t.Fatalf("a poll with the wrong secret exited with %d:\n%s", code, errOut)
	}
	if got := lastTransactionState(t, captureFile, id); got != capture.TransactionWaiting {
		t.Errorf("after a wrong secret the capture file records the transaction as %q, want waiting", got)
	}
	useSecret(t, testSecret)
	if code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile); code != exitOK {
		t.Fatalf("poll exited with %d:\n%s", code, errOut)
	}
	readCert(t, certOut)

	rejecting := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--reject", "badRequest", "--waiting", "1", "--check-after", "0s")
	code, out, errOut = run(t, "enroll", "--server", rejecting.url, "--ref", testRef, "--cert-out", filepath.Join(dir, "rejected.pem"),
		"--key-out", filepath.Join(dir, "rejected.key"), "--poll-later", "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	id = transactionIDIn(t, out)
	code, _, errOut = run(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitRejected || !errorContains(errOut, "badRequest") {
		t.Fatalf("poll exited with %d, want %d:\n%s", code, exitRejected, errOut)
	}
	if got := lastTransactionState(t, captureFile, id); got != capture.TransactionEnded {
		t.Errorf("after a rejection the capture file records the transaction as %q, want ended", got)
	}
}

// TestPollErrors checks the errors reported before poll sends anything.
func TestPollErrors(t *testing.T) {
	useSecret(t, testSecret)
	dir := t.TempDir()
	captureFile := filepath.Join(dir, "run.jsonl")
	writeFile(t, captureFile, []byte(strings.Join([]string{
		`{"kind":"start","tool":"certrally","command":"enroll"}`,
		`{"kind":"transaction","id":"0a0b","state":"waiting","resume":{"server":"http://user:xxxxx@127.0.0.1:1/cmp","profile":"compatible","certOut":"/c.pem","state":{}}}`,
		`{"kind":"transaction","id":"0c0d","state":"waiting","resume":{"server":"http://127.0.0.1:1/cmp","profile":"compatible","certOut":"/c.pem"}}`,
		`{"kind":"transaction","id":"0e0f","state":"waiting","resume":{"server":"http://127.0.0.1:1/cmp","profile":"lax","certOut":"/c.pem","state":{}}}`,
		`{"kind":"request","body":"ir","transactionId":"0a1b"}`,
		`{"kind":"response","body":"ip","transactionId":"0a1b"}`,
		`{"kind":"end","exitStatus":0}`,
	}, "\n")+"\n"))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"server password", []string{"poll", "--transaction-id", "0a:0B", "--capture", captureFile}, "pass --server again"},
		{"no state", []string{"poll", "--transaction-id", "0c0d", "--capture", captureFile}, "has no state to resume"},
		{"unknown profile", []string{"poll", "--transaction-id", "0e0f", "--capture", captureFile}, `unknown profile "lax"`},
		{"unknown transaction", []string{"poll", "--transaction-id", "1234", "--capture", captureFile}, "holds no transaction 1234"},
		{"transaction not waiting", []string{"poll", "--transaction-id", "0a1b", "--capture", captureFile}, "did not wait for the CA"},
		{"not hex", []string{"poll", "--transaction-id", "xyz", "--capture", captureFile}, "is not a transaction ID in hex"},
		{"missing capture", []string{"poll", "--transaction-id", "0a0b", "--capture", filepath.Join(dir, "missing.jsonl")}, "--capture:"},
		{"no transaction id", []string{"poll", "--capture", captureFile}, "transaction-id"},
		{"no capture", []string{"poll", "--transaction-id", "0a0b"}, "capture"},
		{"poll later without capture", []string{"enroll", "--server", "http://127.0.0.1:1/cmp", "--ref", testRef,
			"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"), "--poll-later"},
			"--capture is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, tt.args...)
			if code != exitLocal || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d with %q:\n%s", code, exitLocal, tt.want, errOut)
			}
		})
	}
}
