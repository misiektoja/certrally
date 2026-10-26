package cli

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/server"
)

// captureStart returns the start line of the first run in the capture file at path.
func captureStart(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("%s is empty", path)
	}
	var line map[string]any
	if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["kind"] != "start" {
		t.Fatalf("the first line is %v, want the start line", line)
	}
	return line
}

// TestInsecureCMP checks that --insecure accepts an untrusted HTTPS certificate, warns about it and
// records it in the capture file, and that the server is refused without it.
func TestInsecureCMP(t *testing.T) {
	useSecret(t, testSecret)
	ca := startTLSCA(t, nil)
	dir := t.TempDir()
	certOut, keyOut, captureFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "run.jsonl")

	code, doc := runJSON(t, "enroll", "--server", ca.url, "--ref", testRef, "--insecure",
		"--cert-out", certOut, "--key-out", keyOut, "--capture", captureFile)
	if code != exitOK {
		t.Fatalf("enroll --insecure exited with %d: %v", code, doc["error"])
	}
	if !hasWarning(doc, "not checked because of --insecure") {
		t.Errorf("the document does not warn about --insecure: %v", doc["warnings"])
	}
	readCert(t, certOut)
	if start := captureStart(t, captureFile); start["insecure"] != true {
		t.Errorf("the capture start line does not record --insecure: %v", start)
	}

	code, out, errOut := run(t, "ping", "--server", ca.url, "--insecure")
	if code != exitOK || !strings.Contains(errOut, "not checked because of --insecure") {
		t.Errorf("ping --insecure exited with %d:\n%s%s", code, errOut, out)
	}

	code, doc = runJSON(t, "cacerts", "--server", ca.url, "--ref", testRef, "--capture", captureFile)
	if code != exitTransport || !strings.Contains(text(get(doc, "error.hint")), "--insecure skips the check") {
		t.Errorf("without --insecure: exit %d, error %v", code, doc["error"])
	}
	f, err := os.Open(captureFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	var starts []bool
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		if line["kind"] == "start" {
			_, insecure := line["insecure"]
			starts = append(starts, insecure)
		}
	}
	if len(starts) != 2 || !starts[0] || starts[1] {
		t.Errorf("the start lines record --insecure as %v, want it only for the first run", starts)
	}

	code, _, errOut = run(t, "ping", "--server", ca.url, "--insecure", "--tls-ca-cert", ca.caFile)
	if code != exitLocal || !errorContains(errOut, "none of the others can be") {
		t.Errorf("--insecure with --tls-ca-cert exited with %d:\n%s", code, errOut)
	}
}

// TestInsecurePoll checks that poll takes --insecure for the HTTPS server of a waiting transaction.
func TestInsecurePoll(t *testing.T) {
	useSecret(t, testSecret)
	ca := startTLSCA(t, func(m *mockserver.MockCA) server.CA {
		return &faultCA{MockCA: m, waiting: 1, pending: map[string]*pendingDecision{}}
	})
	dir := t.TempDir()
	certOut, keyOut, captureFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "run.jsonl")
	code, doc := runJSON(t, "enroll", "--server", ca.url, "--ref", testRef, "--insecure", "--poll-later",
		"--cert-out", certOut, "--key-out", keyOut, "--capture", captureFile)
	id, _ := get(doc, "result.transactionId").(string)
	if code != exitOK || get(doc, "result.status") != "waiting" || id == "" {
		t.Fatalf("enroll exited with %d: %v", code, doc)
	}

	code, doc = runJSON(t, "poll", "--transaction-id", id, "--capture", captureFile)
	if code != exitTransport {
		t.Errorf("poll without --insecure exited with %d: %v", code, doc["error"])
	}
	code, doc = runJSON(t, "poll", "--transaction-id", id, "--capture", captureFile, "--insecure")
	if code != exitOK || !hasWarning(doc, "not checked because of --insecure") {
		t.Fatalf("poll --insecure exited with %d: %v %v", code, doc["error"], doc["warnings"])
	}
	readCert(t, certOut)
}

// TestInsecureEST checks that --insecure accepts the untrusted certificate of an EST server, warns
// about it and marks the CA certificates unverified, and the flags it cannot be combined with.
func TestInsecureEST(t *testing.T) {
	usePassword(t, estTestPassword)
	srv := startESTServer(t, nil, nil, nil)
	dir := t.TempDir()
	base := []string{"est", "cacerts", "--server", srv.url}

	code, doc := runJSON(t, "est", "csrattrs", "--server", srv.url)
	if code != exitTransport || !strings.Contains(text(get(doc, "error.hint")), "--insecure skips the check") {
		t.Errorf("without --insecure: exit %d, error %v", code, doc["error"])
	}

	out := filepath.Join(dir, "ca.pem")
	code, doc = runJSON(t, append(base, "--insecure", "--out", out)...)
	if code != exitOK || get(doc, "result.verified") != "none" || get(doc, "result.saved.0") != out {
		t.Fatalf("est cacerts --insecure exited with %d: %v %v", code, doc["error"], doc["result"])
	}
	if !hasWarning(doc, "not checked because of --insecure") {
		t.Errorf("the document does not warn about --insecure: %v", doc["warnings"])
	}
	readCert(t, out)

	code, stdout, errOut := run(t, "est", "enroll", "--server", srv.url, "--insecure", "--user", estTestUser,
		"--subject", "CN=insecure", "--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))
	if code != exitOK || !strings.Contains(errOut, "not checked because of --insecure") {
		t.Errorf("est enroll --insecure exited with %d:\n%s%s", code, errOut, stdout)
	}
	if ladder, warning := strings.Index(errOut, "simpleenroll"), strings.Index(errOut, "--insecure"); ladder < 0 || warning < ladder {
		t.Errorf("the warning does not follow the ladder:\n%s", errOut)
	}

	for _, extra := range [][]string{
		{"--insecure", "--tls-ca-cert", srv.caFile},
		{"--insecure", "--bootstrap"},
		{"--insecure", "--srp", "--user", estTestUser},
	} {
		code, _, errOut := run(t, append(base, extra...)...)
		if code != exitLocal || !errorContains(errOut, "none of the others can be") {
			t.Errorf("%q exited with %d:\n%s", extra, code, errOut)
		}
	}
}
