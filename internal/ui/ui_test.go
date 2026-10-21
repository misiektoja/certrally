package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/misiektoja/certrally/internal/trace"
)

// plain returns a writer that removes styling, as on a pipe, and the buffer it writes to.
func plain() (*colorprofile.Writer, *bytes.Buffer) {
	var b bytes.Buffer
	return &colorprofile.Writer{Forward: &b, Profile: colorprofile.NoTTY}, &b
}

// TestLadder checks that every line keeps both lifelines in place, whatever the label length.
func TestLadder(t *testing.T) {
	w, b := plain()
	l := NewLadder(w, "certrally", "ca.example.com")
	long := strings.Repeat("x", 200)
	events := []trace.Event{
		{Kind: trace.Request, Size: 500, Message: &trace.Summary{Body: "ir", Protection: "PBMAC1"}},
		{Kind: trace.Response, HTTPStatus: 200, Size: 2048, Elapsed: 40 * time.Millisecond,
			Message: &trace.Summary{Body: "ip", Status: "waiting", Protection: "MLDSA87-ECDSA-P384-SHA512"}},
		{Kind: trace.Response, HTTPStatus: 200, Message: &trace.Summary{Body: "pollRep", CheckAfter: 5, Protection: "ECDSA SHA-256"}},
		{Kind: trace.Response, HTTPStatus: 404, Elapsed: 2 * time.Second, Transport: errors.New(long)},
		{Kind: trace.Response, HTTPStatus: 200, Size: 3},
		{Kind: trace.Failure, Elapsed: time.Second, Transport: errors.New("dial tcp: refused")},
	}
	for _, ev := range events {
		l.Event(ev)
	}
	out := b.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for _, line := range lines[1:] {
		if w := lipgloss.Width(line); w != ladderWidth+4 || !strings.HasSuffix(line, "│") {
			t.Errorf("line of width %d: %q", w, line)
		}
	}
	for _, want := range []string{"certrally", "ca.example.com", "ir  PBMAC1  500 B", "ip  waiting", "2.0 KiB  40 ms", "checkAfter 5s", "...", "not a CMP message", "refused", "1.0 s"} {
		if !strings.Contains(out, want) {
			t.Errorf("ladder lacks %q:\n%s", want, out)
		}
	}
}

// TestReport checks alignment and that empty fields are left out.
func TestReport(t *testing.T) {
	w, b := plain()
	Report(w, false, "Failed", []Field{{Name: "A", Value: "1"}, {Name: "Longer", Value: "2"}, {Name: "Empty"}})
	want := "✗ Failed\n  A       1\n  Longer  2\n"
	if b.String() != want {
		t.Errorf("Report wrote %q, want %q", b.String(), want)
	}
}

// TestSanitize checks that terminal control sequences and long text are neutralized.
func TestSanitize(t *testing.T) {
	tests := map[string]string{
		"plain text":             "plain text",
		"\x1b[31mred\x1b[0m":     "\uFFFD[31mred\uFFFD[0m",
		"line\nbreak\ttab":       "line\uFFFDbreak\uFFFDtab",
		"bad \xff byte":          "bad \uFFFD byte",
		"zażółć":                 "zażółć",
		strings.Repeat("a", 400): strings.Repeat("a", maxPeerText-3) + "...",
	}
	for in, want := range tests {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSection checks that section fields are indented below their heading and aligned.
func TestSection(t *testing.T) {
	w, b := plain()
	Section(w, "CN=CA", []Field{{Name: "Key", Value: "ML-DSA-65"}, {Name: "SHA-256", Value: "AB"}, {Name: "Empty"}})
	want := "  CN=CA\n    Key      ML-DSA-65\n    SHA-256  AB\n"
	if b.String() != want {
		t.Errorf("Section wrote %q, want %q", b.String(), want)
	}
}

// TestHeading checks a heading with and without details.
func TestHeading(t *testing.T) {
	w, b := plain()
	Heading(w, "→ ir", "run.jsonl:2  PBMAC1")
	Heading(w, "← ip", "")
	if want := "→ ir  run.jsonl:2  PBMAC1\n← ip\n"; b.String() != want {
		t.Errorf("Heading wrote %q, want %q", b.String(), want)
	}
}

// TestLadderEST checks the labels of a TLS connection, EST messages and a note.
func TestLadderEST(t *testing.T) {
	w, b := plain()
	l := NewLadder(w, "certrally", "est.example.com:8443")
	retry := 30
	events := []trace.Event{
		{Kind: trace.Connect, TLS: &trace.TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", Server: "CN=est.example.com"}},
		{Kind: trace.Request, Size: 400, EST: &trace.ESTSummary{Method: "POST", Operation: "simpleenroll", Content: "pkcs10", Subject: "CN=device-42"}},
		{Kind: trace.Response, HTTPStatus: 202, Elapsed: 5 * time.Millisecond, EST: &trace.ESTSummary{RetryAfter: &retry}},
		{Kind: trace.Response, HTTPStatus: 200, Size: 1500, EST: &trace.ESTSummary{Content: "certs-only", Certificates: 1}},
		{Kind: trace.Response, HTTPStatus: 401, EST: &trace.ESTSummary{Text: "wrong\x1b[2J password"}},
		{Kind: trace.Response, HTTPStatus: 204, EST: &trace.ESTSummary{}},
		{Kind: trace.Request, EST: &trace.ESTSummary{Method: "GET", Operation: "cacerts", Label: "ca1"}},
	}
	for _, ev := range events {
		l.Event(ev)
	}
	l.Note("waiting 30 s as the server asked")
	out := b.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for _, line := range lines[1:] {
		if w := lipgloss.Width(line); w != ladderWidth+4 || !strings.HasSuffix(line, "│") {
			t.Errorf("line of width %d: %q", w, line)
		}
	}
	for _, want := range []string{
		"TLS 1.3  TLS_AES_128_GCM_SHA256  CN=est.example.com", "◀", "simpleenroll  POST  CN=device-42  400 B",
		"HTTP 202 Accepted  retry after 30 s", "certs-only  1 certificate", "HTTP 401 Unauthorized  \"wrong�[2J password\"",
		"HTTP 204 No Content", "ca1/cacerts  GET", "waiting 30 s as the server asked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ladder lacks %q:\n%s", want, out)
		}
	}
}
