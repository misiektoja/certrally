package cli

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/server"

	"github.com/misiektoja/certrally/internal/pemfile"
)

// TestLintConforming checks that the responses of the example CA break no rule.
func TestLintConforming(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	capture, _ := recordCapture(t, ca)

	code, doc := runJSON(t, "lint", capture, "--ca-cert", ca.caFile)
	if code != exitOK || get(doc, "result.checked") != float64(6) || get(doc, "result.skipped") != float64(0) ||
		len(get(doc, "result.findings").([]any)) != 0 {
		t.Errorf("exited with %d: %v", code, doc)
	}
	code, out, errOut := run(t, "lint", capture)
	if code != exitOK || !strings.Contains(out, "No deviations in 6 responses") || errOut != "" {
		t.Errorf("exited with %d:\n%s%s", code, errOut, out)
	}
	if code, out, errOut := run(t, "lint", capture, "-q"); code != exitOK || out != "" || errOut != "" {
		t.Errorf("-q exited with %d:\n%s%s", code, errOut, out)
	}
}

// TestLintCapturedDeviation checks that lint reports the deviation that the run warned about.
func TestLintCapturedDeviation(t *testing.T) {
	const deviation = "The ip response carries no extraCerts, so the chain of the new certificate is missing"
	useSecret(t, testSecret)
	var issuing intermediateCA
	ca := startCA(t, func(m *mockserver.MockCA) server.CA {
		issuing = newIntermediateCA(t, m)
		return issuing
	})
	dir := t.TempDir()
	chainFile, capture := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "run.jsonl")
	writeFile(t, chainFile, pemfile.EncodeCertificates([]*x509.Certificate{issuing.cert, issuing.Cert()}))
	code, _, errOut := run(t, "enroll", "--server", stripExtraCerts(t, ca.url), "--ref", testRef, "--ca-cert", chainFile,
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"), "--capture", capture)
	if code != exitOK || !strings.Contains(errOut, deviation) {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}

	for _, args := range [][]string{{capture}, {capture, "--ca-cert", chainFile}} {
		code, doc := runJSON(t, append([]string{"lint"}, args...)...)
		if code != exitProfile || get(doc, "result.findings.0.text") != deviation ||
			get(doc, "result.findings.0.rule") != "RFC 9483 section 3.3" || get(doc, "result.findings.0.source") != capture+":3" ||
			get(doc, "result.findings.1") != nil || get(doc, "error.title") != "1 deviation in 2 responses" {
			t.Errorf("%v exited with %d: %v", args, code, doc)
		}
	}
	code, out, errOut := run(t, "lint", capture)
	if code != exitProfile || !strings.Contains(out, capture+":3: "+deviation+" (RFC 9483 section 3.3).") ||
		!strings.Contains(errOut, "1 deviation in 2 responses") {
		t.Errorf("exited with %d:\n%s%s", code, errOut, out)
	}
}

// TestLintRejection checks a rejection, which ends a run before any certificate.
func TestLintRejection(t *testing.T) {
	useSecret(t, testSecret)
	capture := filepath.Join(t.TempDir(), "run.jsonl")
	code, _, _ := run(t, "cacerts", "--server", rejectingServer(t, badRequest), "--ref", testRef, "--capture", capture, "-q")
	if code != exitRejected {
		t.Fatalf("cacerts exited with %d", code)
	}
	code, doc := runJSON(t, "lint", capture)
	if code != exitProfile || get(doc, "result.findings.0.text") != "The error response has a senderNonce of 64 bits instead of at least 128" {
		t.Errorf("exited with %d: %v", code, doc)
	}
}

// TestLintMessageFiles checks message files given in exchange order.
func TestLintMessageFiles(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	first, _ := recordCapture(t, ca)
	second, _ := recordCapture(t, ca)
	dir := t.TempDir()
	file := func(capture string, i int) string {
		m := readCapture(t, capture)[i]
		path := filepath.Join(dir, filepath.Base(filepath.Dir(capture))+"-"+m.Msg.Body.Type.String()+".der")
		writeFile(t, path, m.DER)
		return path
	}
	ir, ip, otherIP := file(first, 0), file(first, 1), file(second, 1)

	if code, doc := runJSON(t, "lint", ir, ip); code != exitOK || get(doc, "result.checked") != float64(1) {
		t.Errorf("matching pair exited with %d: %v", code, doc)
	}
	code, doc := runJSON(t, "lint", ir, otherIP)
	findings, _ := get(doc, "result.findings").([]any)
	texts := make([]string, 0, len(findings))
	for _, f := range findings {
		texts = append(texts, get(f, "text").(string))
	}
	want := "The ip response has a different transactionID than the request; " +
		"The ip response has a recipNonce that is not the senderNonce of the request"
	if code != exitProfile || strings.Join(texts, "; ") != want {
		t.Errorf("mismatched pair exited with %d: %q", code, texts)
	}

	code, out, errOut := run(t, "lint", ip)
	if code != exitLocal || out != "" || !strings.Contains(errOut, "the ip response has no request before it") ||
		!strings.Contains(errOut, "No response was checked") {
		t.Errorf("lone response exited with %d:\n%s%s", code, errOut, out)
	}
	code, doc = runJSON(t, "lint", ip, ir, otherIP)
	if code != exitProfile || get(doc, "result.skipped") != float64(1) || get(doc, "result.checked") != float64(1) {
		t.Errorf("skipped response exited with %d: %v", code, doc)
	}
}
