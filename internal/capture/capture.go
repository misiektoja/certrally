// Package capture writes the messages of a CMP or EST exchange to a file, so that they can be
// inspected or replayed later.
//
// A capture file holds JSON Lines. Each run appends a "start" line, one line per message event in
// the trace.Record form with the message bytes and an "end" line with the exit status. A file can
// hold several runs.
package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/misiektoja/certrally/internal/trace"
)

// Format is the version of the capture format written in every start line.
const Format = 1

// Start describes a run. It is the first line the run writes.
type Start struct {
	// Kind is always "start".
	Kind   string `json:"kind"`
	Format int    `json:"format"`
	// Protocol is "est" for an EST run. It is absent for a CMP run.
	Protocol string    `json:"protocol,omitempty"`
	Tool     string    `json:"tool"`
	Version  string    `json:"version,omitempty"`
	Command  string    `json:"command"`
	Server   string    `json:"server"`
	Time     time.Time `json:"time"`
}

// End records how a run finished. It is the last line the run writes.
type End struct {
	// Kind is always "end".
	Kind       string    `json:"kind"`
	Time       time.Time `json:"time"`
	ExitStatus int       `json:"exitStatus"`
}

// Writer appends one run to a capture file.
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	err  error
	done bool
}

// Open opens path for appending, creating it with mode 0600 because captured MAC-protected messages
// allow offline guessing of the shared secret. It writes the start line of the run.
func Open(path string, start Start) (*Writer, error) {
	flags := os.O_WRONLY | os.O_APPEND | os.O_CREATE
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: the user names the file.
	if err != nil {
		return nil, err
	}
	w := &Writer{f: f, enc: json.NewEncoder(f)}
	w.enc.SetEscapeHTML(false)
	start.Kind, start.Format = "start", Format
	if err := w.write(start); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return w, nil
}

// Event appends a message event with its bytes. After a write error it does nothing. Close then
// returns that error.
func (w *Writer) Event(ev trace.Event) {
	_ = w.write(ev.Record(true))
}

// Close writes the end line and closes the file. It returns the first error of the run.
func (w *Writer) Close(exitStatus int) error {
	_ = w.write(End{Kind: "end", Time: time.Now().UTC(), ExitStatus: exitStatus})
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.done {
		w.done = true
		w.err = errors.Join(w.err, w.f.Close())
	}
	return w.err
}

// write appends one line unless an earlier write failed or the run is closed.
func (w *Writer) write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil || w.done {
		return w.err
	}
	w.err = w.enc.Encode(v)
	return w.err
}
