// Package ui renders the ladder view of a CMP exchange and the result reports of certrally.
package ui

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"charm.land/lipgloss/v2"

	"github.com/misiektoja/certrally/internal/trace"
)

// Styles use the basic ANSI colours so that they follow the terminal theme.
var (
	faint   = lipgloss.NewStyle().Faint(true)
	bold    = lipgloss.NewStyle().Bold(true)
	request = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	good    = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	warn    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	bad     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

// ladderWidth is the number of columns between the two lifelines.
const ladderWidth = 64

// Ladder draws a sequence diagram of an exchange, one message at a time, so that slow steps such as
// polling show up while they happen.
type Ladder struct {
	w io.Writer
}

// NewLadder writes the diagram header naming both sides and returns a ladder that writes to w.
func NewLadder(w io.Writer, client, server string) *Ladder {
	client = truncate(Sanitize(client), ladderWidth/2-2)
	server = truncate(Sanitize(server), ladderWidth/2-2)
	gap := max(ladderWidth+2-utf8.RuneCountInString(client)-utf8.RuneCountInString(server), 1)
	_, _ = fmt.Fprintf(w, "  %s%s%s\n", bold.Render(client), strings.Repeat(" ", gap), bold.Render(server))
	l := &Ladder{w: w}
	l.line("", false)
	return l
}

// Event draws one recorded event.
func (l *Ladder) Event(ev trace.Event) {
	switch ev.Kind {
	case trace.Request:
		l.line(requestLabel(ev), false)
		l.arrow(request, false)
	case trace.Response:
		text, style := responseLabel(ev)
		l.line(text, true)
		l.arrow(style, true)
	case trace.Failure:
		l.line(label(bad, Sanitize(ev.Transport.Error()), ""), false)
		l.line(label(bad, "─ ─ ─ ✗ no response after "+formatDuration(ev.Elapsed), ""), false)
	}
}

// requestLabel describes a request message.
func requestLabel(ev trace.Event) string {
	if ev.Message == nil {
		return label(request, "request", formatSize(ev.Size))
	}
	return label(request, ev.Message.Body, ev.Message.Protection+"  "+formatSize(ev.Size))
}

// responseLabel describes a response and returns the style its arrow uses.
func responseLabel(ev trace.Event) (string, lipgloss.Style) {
	timing := formatDuration(ev.Elapsed)
	if ev.Transport != nil {
		return label(bad, Sanitize(ev.Transport.Error()), timing), bad
	}
	m := ev.Message
	if m == nil {
		head := fmt.Sprintf("HTTP %d, not a CMP message", ev.HTTPStatus)
		return label(bad, head, formatSize(ev.Size)+"  "+timing), bad
	}
	style := good
	parts := []string{m.Body}
	switch {
	case m.Body == "error" || m.Status == "rejection":
		style = bad
	case m.Body == "pollRep" || m.Status == "waiting":
		style = warn
	}
	if m.Status != "" {
		parts = append(parts, m.Status)
	}
	if m.FailInfo != 0 {
		parts = append(parts, m.FailInfo.String())
	}
	if m.Body == "pollRep" {
		parts = append(parts, fmt.Sprintf("checkAfter %ds", m.CheckAfter))
	}
	if ev.HTTPStatus != 200 {
		parts = append(parts, fmt.Sprintf("HTTP %d", ev.HTTPStatus))
	}
	return label(style, strings.Join(parts, "  "), m.Protection+"  "+formatSize(ev.Size)+"  "+timing), style
}

// label joins a highlighted head and faint details, shortening the head so that both fit between
// the lifelines.
func label(style lipgloss.Style, head, details string) string {
	if details == "" {
		return style.Render(truncate(head, ladderWidth-2))
	}
	details = "  " + details
	room := ladderWidth - 2 - utf8.RuneCountInString(details)
	return style.Render(truncate(head, max(room, 8))) + faint.Render(details)
}

// line writes text between the lifelines, left-aligned or right-aligned.
func (l *Ladder) line(text string, right bool) {
	pad := max(ladderWidth-2-lipgloss.Width(text), 0)
	var body string
	if right {
		body = strings.Repeat(" ", pad) + text
	} else {
		body = text + strings.Repeat(" ", pad)
	}
	_, _ = fmt.Fprintf(l.w, "  %s %s %s\n", faint.Render("│"), body, faint.Render("│"))
}

// arrow writes an arrow from client to server. With back set it points from server to client.
func (l *Ladder) arrow(style lipgloss.Style, back bool) {
	shaft := strings.Repeat("─", ladderWidth-3)
	var a string
	if back {
		a = "◀" + shaft
	} else {
		a = shaft + "▶"
	}
	_, _ = fmt.Fprintf(l.w, "  %s %s %s\n", faint.Render("│"), style.Render(a), faint.Render("│"))
}

// formatSize returns a byte count for display.
func formatSize(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f KiB", float64(n)/1024)
}

// formatDuration returns a round-trip time for display.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1f s", d.Seconds())
}

// Field is one line of a report.
type Field struct {
	Name, Value string
}

// Report writes a title marked as success or failure, followed by aligned fields. Empty values are
// skipped. Values must already be sanitized if they come from the peer.
func Report(w io.Writer, ok bool, title string, fields []Field) {
	mark, style := "✓", good
	if !ok {
		mark, style = "✗", bad
	}
	_, _ = fmt.Fprintf(w, "%s %s\n", style.Render(mark), bold.Render(title))
	writeFields(w, "  ", fields)
}

// Answer writes an answer to a question of an interactive form.
func Answer(w io.Writer, question, answer string) {
	_, _ = fmt.Fprintf(w, "%s %s  %s\n", good.Render("✓"), faint.Render(question), answer)
}

// Section writes a heading under a report, followed by its fields indented below it.
func Section(w io.Writer, heading string, fields []Field) {
	_, _ = fmt.Fprintf(w, "  %s\n", bold.Render(heading))
	writeFields(w, "    ", fields)
}

// Heading writes a bold title followed by faint details, for a report that is neither a success
// nor a failure. Values must already be sanitized if they come from the peer.
func Heading(w io.Writer, title, details string) {
	if details != "" {
		details = "  " + faint.Render(details)
	}
	_, _ = fmt.Fprintf(w, "%s%s\n", bold.Render(title), details)
}

// writeFields writes the non-empty fields with their names aligned.
func writeFields(w io.Writer, indent string, fields []Field) {
	width := 0
	for _, f := range fields {
		if f.Value != "" {
			width = max(width, len(f.Name))
		}
	}
	for _, f := range fields {
		if f.Value == "" {
			continue
		}
		name := f.Name + strings.Repeat(" ", width-len(f.Name))
		_, _ = fmt.Fprintf(w, "%s%s  %s\n", indent, faint.Render(name), f.Value)
	}
}

// Warning writes a highlighted warning line.
func Warning(w io.Writer, text string) {
	_, _ = fmt.Fprintf(w, "%s %s\n", warn.Render("!"), text)
}

// maxPeerText bounds peer-supplied text so that a hostile server cannot flood the terminal.
const maxPeerText = 300

// Sanitize makes peer-controlled text safe to print: control characters, including the escape
// sequences that could rewrite the terminal, become U+FFFD and long text is cut short.
func Sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return '�'
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	return truncate(s, maxPeerText)
}

// truncate shortens s to at most n runes, marking the cut with "...".
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n <= 3 {
		return string([]rune(s)[:n])
	}
	return string([]rune(s)[:n-3]) + "..."
}
