package capture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/certrally/internal/trace"
)

// readLines decodes every line of a capture file into a map.
func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines = append(lines, line)
	}
	return lines
}

// TestWriter checks the lines of two runs appended to one file and the file mode.
func TestWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	body := []byte{0x30, 0x03, 0x02, 0x01, 0x02}
	for run := range 2 {
		w, err := Open(path, Start{Tool: "certrally", Command: "ping", Server: "http://ca.test/cmp", Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		w.Event(trace.Event{Kind: trace.Request, Time: time.Now(), Size: len(body), DER: body})
		w.Event(trace.Event{Kind: trace.Failure, Time: time.Now(), Elapsed: time.Millisecond, Transport: errors.New("refused")})
		if err := w.Close(run + 2); err != nil {
			t.Fatal(err)
		}
		w.Event(trace.Event{Kind: trace.Request})
		if err := w.Close(0); err != nil {
			t.Errorf("second Close: %v", err)
		}
	}

	lines := readLines(t, path)
	kinds := make([]any, 0, len(lines))
	for _, l := range lines {
		kinds = append(kinds, l["kind"])
	}
	want := []any{"start", "request", "failure", "end", "start", "request", "failure", "end"}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("kinds = %v, want %v", kinds, want)
		}
	}
	if lines[0]["format"] != float64(Format) || lines[0]["command"] != "ping" {
		t.Errorf("start line = %v", lines[0])
	}
	if lines[1]["der"] != "MAMCAQI=" || lines[2]["problem"] != "refused" {
		t.Errorf("event lines = %v %v", lines[1], lines[2])
	}
	if lines[3]["exitStatus"] != float64(2) || lines[7]["exitStatus"] != float64(3) {
		t.Errorf("end lines = %v %v", lines[3], lines[7])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// TestOpenError checks that a file that cannot be created is reported before anything is sent.
func TestOpenError(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing", "run.jsonl"), Start{}); err == nil {
		t.Error("Open succeeded in a missing directory")
	}
}

// TestWriterProtocol checks that an EST run names its protocol and a CMP run leaves it out.
func TestWriterProtocol(t *testing.T) {
	for _, protocol := range []string{"", "est"} {
		path := filepath.Join(t.TempDir(), "run.jsonl")
		w, err := Open(path, Start{Protocol: protocol, Tool: "certrally", Command: "est cacerts", Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(0); err != nil {
			t.Fatal(err)
		}
		got, ok := readLines(t, path)[0]["protocol"]
		if protocol == "" && ok || protocol != "" && got != protocol {
			t.Errorf("protocol %q: start line has %v", protocol, got)
		}
	}
}

// TestFindTransaction checks that the last line of a transaction across runs holds its state and
// that other files report the transaction or the line they cannot use.
func TestFindTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	lines := []Transaction{
		{ID: "0a0b", State: TransactionWaiting, Resume: json.RawMessage(`{"n":1}`)},
		{ID: "ffee", State: TransactionWaiting, Resume: json.RawMessage(`{"n":2}`)},
		{ID: "0a0b", State: TransactionWaiting, Resume: json.RawMessage(`{"n":3}`)},
		{ID: "ffee", State: TransactionEnded},
	}
	for _, line := range lines {
		w, err := Open(path, Start{Tool: "certrally", Command: "poll", Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Transaction(line); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(0); err != nil {
			t.Fatal(err)
		}
	}
	got, err := FindTransaction(path, "0a0b")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "transaction" || got.State != TransactionWaiting || string(got.Resume) != `{"n":3}` || got.Time.IsZero() {
		t.Errorf("FindTransaction(0a0b) = %+v, want the third line", got)
	}
	if got, err := FindTransaction(path, "ffee"); err != nil || got.State != TransactionEnded || got.Resume != nil {
		t.Errorf("FindTransaction(ffee) = %+v, %v, want the ended line", got, err)
	}
	if _, err := FindTransaction(path, "0c0d"); !errors.Is(err, ErrNoTransaction) {
		t.Errorf("FindTransaction(0c0d) returned %v, want ErrNoTransaction", err)
	}
	decided := filepath.Join(t.TempDir(), "decided.jsonl")
	if err := os.WriteFile(decided, []byte(strings.Join([]string{
		`{"kind":"start","tool":"certrally","command":"enroll"}`,
		`{"kind":"request","body":"ir","transactionId":"0c0d"}`,
		`{"kind":"response","body":"ip","transactionId":"0c0d"}`,
		`{"kind":"end","exitStatus":0}`,
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FindTransaction(decided, "0c0d"); !errors.Is(err, ErrNotWaiting) {
		t.Errorf("FindTransaction on messages without a transaction line returned %v, want ErrNotWaiting", err)
	}
	if _, err := FindTransaction(decided, "0a0b"); !errors.Is(err, ErrNoTransaction) {
		t.Errorf("FindTransaction(0a0b) on another transaction's messages returned %v, want ErrNoTransaction", err)
	}
	if _, err := FindTransaction(filepath.Join(t.TempDir(), "missing.jsonl"), "0a0b"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("FindTransaction on a missing file returned %v", err)
	}
	broken := filepath.Join(t.TempDir(), "broken.jsonl")
	if err := os.WriteFile(broken, []byte("{\"kind\":\"start\"}\n\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FindTransaction(broken, "0a0b"); err == nil || !strings.Contains(err.Error(), "broken.jsonl:3") {
		t.Errorf("FindTransaction on a broken file returned %v, want the line number", err)
	}
}
