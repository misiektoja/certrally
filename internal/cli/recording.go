package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/misiektoja/certrally/internal/capture"
	"github.com/misiektoja/certrally/internal/profile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// Protocols as named in capture files and the inspect result.
const (
	protocolCMP = "cmp"
	protocolEST = "est"
)

// recording is what every command that talks to a server shares: the recorder of the exchange, the
// ladder that draws it, the capture file and the profile warnings.
type recording struct {
	p *printer
	// server is the server URL without any password. host names the server in the ladder.
	server  string
	host    string
	profile string
	// recorder records every exchange.
	recorder *trace.Recorder
	// ladder draws the exchange in text output without --quiet.
	ladder *ui.Ladder
	// capture records the exchange for --capture.
	capture *capture.Writer
	// observe, when set, sees each event before the capture and the ladder do.
	observe func(trace.Event)
	// warned holds the profile deviations already reported as warnings.
	warned map[string]bool
	// pending holds the warnings that wait for the ladder to end, so they do not split it.
	pending []string
}

// insecureWarning is reported when --insecure skips the check of the server certificate.
const insecureWarning = "The TLS certificate of the server was not checked because of --insecure. " +
	"Anyone who intercepts the connection can pose as the server."

// recordingOptions say what a recording records and where.
type recordingOptions struct {
	// server is the URL the user gave.
	server   string
	profile  string
	capture  string
	protocol trace.Protocol
	// insecure records that --insecure skipped the check of the server certificate. The capture file
	// notes it and the report warns about it once the ladder ends.
	insecure bool
}

// openRecording starts recording the exchange with a server and registers it with p, so that the
// output of the command includes it.
func openRecording(p *printer, o recordingOptions) (*recording, error) {
	rec := &recording{
		p:       p,
		server:  redactURL(o.server),
		host:    urlHost(o.server),
		profile: o.profile,
		warned:  map[string]bool{},
	}
	if o.capture != "" {
		protocol := ""
		if o.protocol == trace.EST {
			protocol = protocolEST
		}
		w, err := capture.Open(o.capture, capture.Start{
			Protocol: protocol,
			Tool:     programName,
			Version:  toolVersion(),
			Command:  p.command,
			Server:   rec.server,
			Insecure: o.insecure,
			Time:     time.Now().UTC(),
		})
		if err != nil {
			return nil, fmt.Errorf("--capture: %w", err)
		}
		rec.capture = w
	}
	if o.insecure {
		rec.pending = append(rec.pending, insecureWarning)
	}
	rec.recorder = &trace.Recorder{Protocol: o.protocol}
	rec.recorder.OnEvent = func(ev trace.Event) {
		if rec.observe != nil {
			rec.observe(ev)
		}
		if rec.capture != nil {
			rec.capture.Event(ev)
		}
		if rec.ladder != nil {
			rec.ladder.Event(ev)
		}
	}
	p.rec = rec
	return rec, nil
}

// recordTransaction appends a transaction line with the state and the resume record to the capture
// file. It does nothing without --capture.
func (rec *recording) recordTransaction(state string, id []byte, resume any) error {
	if rec.capture == nil {
		return nil
	}
	t := capture.Transaction{ID: hex.EncodeToString(id), State: state}
	if resume != nil {
		data, err := json.Marshal(resume)
		if err != nil {
			return err
		}
		t.Resume = data
	}
	return rec.capture.Transaction(t)
}

// redactURL returns a URL without any password it contains.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return u.Redacted()
}

// urlHost returns the host of a URL for display.
func urlHost(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return u.Host
}

// report handles the profile deviations of a response. A strict recording returns them as an error
// that stops the response, unless stop is false. Otherwise each deviation becomes a warning once.
func (rec *recording) report(findings []profile.Finding, stop bool) error {
	if len(findings) == 0 {
		return nil
	}
	if rec.profile == profile.Strict && stop {
		return &profileError{findings: findings}
	}
	for _, f := range findings {
		text := f.String()
		switch {
		case rec.warned[text]:
		case rec.ladder != nil:
			rec.pending = append(rec.pending, text)
		default:
			rec.p.warn(text)
		}
		rec.warned[text] = true
	}
	return nil
}

// startLadder starts drawing the exchange in text output without --quiet.
func (rec *recording) startLadder() {
	if rec.p.showProgress() {
		rec.ladder = ui.NewLadder(rec.p.stderr, programName, rec.host)
	}
}

// endLadder separates the ladder from the report that follows it and prints the warnings that
// waited for it.
func (rec *recording) endLadder() {
	if rec.ladder != nil && len(rec.recorder.Events()) > 0 {
		_, _ = fmt.Fprintln(rec.p.stderr)
	}
	rec.ladder = nil
	rec.flushWarnings()
}

// flushWarnings prints the warnings that waited for the ladder to end. A command without a ladder
// calls it before its report.
func (rec *recording) flushWarnings() {
	for _, text := range rec.pending {
		rec.p.warn(text)
	}
	rec.pending = nil
}
