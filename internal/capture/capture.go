// Package capture writes the messages of a CMP or EST exchange to a file, so that they can be
// inspected or replayed later.
//
// A capture file holds JSON Lines. Each run appends a "start" line, one line per message event in
// the trace.Record form with the message bytes and an "end" line with the exit status. A run that
// leaves a transaction for a later run, or ends one, appends a "transaction" line before its end
// line. A file can hold several runs.
package capture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// States of a transaction line.
const (
	// TransactionWaiting marks a transaction the CA has not decided, which a later run can resume.
	TransactionWaiting = "waiting"
	// TransactionEnded marks a transaction that a run resumed and ended.
	TransactionEnded = "ended"
)

// Transaction records the state of a transaction that outlives its run.
type Transaction struct {
	// Kind is always "transaction".
	Kind string    `json:"kind"`
	Time time.Time `json:"time"`
	// ID is the transaction ID in lower-case hex.
	ID string `json:"id"`
	// State is TransactionWaiting or TransactionEnded.
	State string `json:"state"`
	// Resume holds what a run needs to resume a waiting transaction. It is absent once the
	// transaction ended.
	Resume json.RawMessage `json:"resume,omitempty"`
}

// ErrNoTransaction reports a capture file without a line for the transaction ID asked for.
var ErrNoTransaction = errors.New("no such transaction")

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

// Transaction appends a transaction line. It returns the first error of the run, because a lost
// transaction line leaves a later run nothing to resume.
func (w *Writer) Transaction(t Transaction) error {
	t.Kind = "transaction"
	if t.Time.IsZero() {
		t.Time = time.Now().UTC()
	}
	return w.write(t)
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

// FindTransaction returns the last line of the capture file at path for the transaction id, which
// holds its latest state. It returns ErrNoTransaction when the file has none.
func FindTransaction(path, id string) (*Transaction, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the user names the file.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var found *Transaction
	r := bufio.NewReader(f)
	for n := 1; ; n++ {
		text, err := r.ReadBytes('\n')
		if text = bytes.TrimSpace(text); len(text) > 0 {
			var line Transaction
			if jsonErr := json.Unmarshal(text, &line); jsonErr != nil {
				return nil, fmt.Errorf("%s:%d: not a capture line: %w", path, n, jsonErr)
			}
			if line.Kind == "transaction" && line.ID == id {
				found = &line
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if found == nil {
		return nil, ErrNoTransaction
	}
	return found, nil
}
