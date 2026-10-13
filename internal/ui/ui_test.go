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
