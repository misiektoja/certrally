package cmpfile

import (
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// encode returns the DER of a message with body from a fixed sender.
func encode(t *testing.T, body *pkicmp.PKIBody) []byte {
	t.Helper()
	msg := pkicmp.NewPKIMessage(body, pkicmp.MessageOptions{Sender: pkicmp.NewDirectoryName(pkix.Name{CommonName: "device"})})
	der, err := msg.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// captureLines returns a capture file with one line per value.
func captureLines(t *testing.T, lines ...any) []byte {
	t.Helper()
	var b strings.Builder
	for _, line := range lines {
		data, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// TestIsRequest checks the direction of every body type. A client sends popdecr to answer the
// popdecc challenge of the CA. A nested body can travel either way and counts as a response.
func TestIsRequest(t *testing.T) {
	requests := []pkicmp.BodyType{
		pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR, pkicmp.BodyTypeRR,
		pkicmp.BodyTypeCertConf, pkicmp.BodyTypePollReq, pkicmp.BodyTypeGenM, pkicmp.BodyTypePopDecR,
	}
	responses := []pkicmp.BodyType{
		pkicmp.BodyTypeIP, pkicmp.BodyTypeCP, pkicmp.BodyTypeKUP, pkicmp.BodyTypeRP, pkicmp.BodyTypePKIConf,
		pkicmp.BodyTypeError, pkicmp.BodyTypePollRep, pkicmp.BodyTypeGenP, pkicmp.BodyTypePopDecC, pkicmp.BodyTypeNested,
	}
	for _, bt := range requests {
		if !IsRequest(bt) {
			t.Errorf("IsRequest(%s) = false", bt)
		}
	}
	for _, bt := range responses {
		if IsRequest(bt) {
			t.Errorf("IsRequest(%s) = true", bt)
		}
	}
}

// TestParseFormats checks that every single-message format yields the message with its direction.
func TestParseFormats(t *testing.T) {
	genm := encode(t, pkicmp.NewGenMBody())
	genp := encode(t, pkicmp.NewGenPBody())
	pemBlocks := string(pem.EncodeToMemory(&pem.Block{Type: "CMP MESSAGE", Bytes: genm})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PKIMESSAGE", Bytes: genp}))
	hexColons := strings.ToUpper(hex.EncodeToString(genp))
	var colons []string
	for i := 0; i < len(hexColons); i += 2 {
		colons = append(colons, hexColons[i:i+2])
	}

	tests := []struct {
		name    string
		data    []byte
		sources string
		bodies  string
		request []bool
	}{
		{"der", genm, "f", "genm", []bool{true}},
		{"base64", []byte(base64.StdEncoding.EncodeToString(genp) + "\n"), "f", "genp", []bool{false}},
		{"base64 lines", []byte(" " + base64.StdEncoding.EncodeToString(genm)[:20] + "\n" + base64.StdEncoding.EncodeToString(genm)[20:]), "f", "genm", []bool{true}},
		{"raw url base64", []byte(base64.RawURLEncoding.EncodeToString(genm)), "f", "genm", []bool{true}},
		{"hex", []byte(hex.EncodeToString(genm) + "\n"), "f", "genm", []bool{true}},
		{"hex with colons", []byte(strings.Join(colons, ":")), "f", "genp", []bool{false}},
		{"pem", []byte(pemBlocks), "f#1 f#2", "genm genp", []bool{true, false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := Parse("f", tt.data)
			if err != nil {
				t.Fatal(err)
			}
			var sources, bodies []string
			for i, m := range msgs {
				sources = append(sources, m.Source)
				bodies = append(bodies, m.Msg.Body.Type.String())
				if m.File != "f" || m.Run != 0 || m.Request != tt.request[i] || !m.Time.IsZero() {
					t.Errorf("message %d = %+v", i, m)
				}
			}
			if strings.Join(sources, " ") != tt.sources || strings.Join(bodies, " ") != tt.bodies {
				t.Errorf("sources %q, bodies %q", sources, bodies)
			}
		})
	}
}

// TestParseCapture checks that a capture yields the CMP messages of each run with their line,
// run and direction, and skips failures and responses that are not CMP messages.
func TestParseCapture(t *testing.T) {
	genm := encode(t, pkicmp.NewGenMBody())
	genp := encode(t, pkicmp.NewGenPBody())
	at := time.Date(2026, 10, 13, 1, 2, 3, 0, time.UTC)
	data := captureLines(t,
		map[string]any{"kind": "start", "format": 1, "server": "https://a.test/cmp"},
		map[string]any{"kind": "request", "time": at, "body": "genm", "der": genm},
		map[string]any{"kind": "response", "httpStatus": 404, "problem": "HTTP 404 Not Found", "der": []byte("<html>")},
		map[string]any{"kind": "end", "exitStatus": 2},
		map[string]any{"kind": "start", "format": 1, "server": "https://b.test/cmp"},
		map[string]any{"kind": "request", "body": "genm", "der": genm},
		map[string]any{"kind": "failure", "problem": "timeout"},
		map[string]any{"kind": "request", "body": "genm", "der": genm},
		map[string]any{"kind": "response", "body": "genp", "der": genp},
		map[string]any{"kind": "end", "exitStatus": 0},
	)
	msgs, err := Parse("run.jsonl", append([]byte("\n"), data...))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		source string
		run    int
		server string
		req    bool
	}{
		{"run.jsonl:3", 1, "https://a.test/cmp", true},
		{"run.jsonl:7", 2, "https://b.test/cmp", true},
		{"run.jsonl:9", 2, "https://b.test/cmp", true},
		{"run.jsonl:10", 2, "https://b.test/cmp", false},
	}
	if len(msgs) != len(want) {
		t.Fatalf("got %d messages, want %d", len(msgs), len(want))
	}
	for i, w := range want {
		m := msgs[i]
		if m.Source != w.source || m.Run != w.run || m.Server != w.server || m.Request != w.req || m.File != "run.jsonl" {
			t.Errorf("message %d = %s run %d %s request %v", i, m.Source, m.Run, m.Server, m.Request)
		}
	}
	if !msgs[0].Time.Equal(at) {
		t.Errorf("time = %v", msgs[0].Time)
	}
}

// TestParseErrors checks the errors for files that hold no CMP message.
func TestParseErrors(t *testing.T) {
	genm := encode(t, pkicmp.NewGenMBody())
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}})
	tests := []struct {
		name, data, want string
	}{
		{"empty", " \n", "f: the file is empty"},
		{"text", "hello world", "not a capture file and not a CMP or EST message"},
		{"json output", "{\n  \"command\": \"enroll\"\n}\n", "record the run with --capture"},
		{"bad json line", `{"kind": "start", "format": 1}` + "\n{oops\n", "f:2: not a capture line"},
		{"no start", `{"kind": "request"}`, "it has no start line"},
		{"newer format", `{"kind": "start", "format": 2}`, "capture format 2 is newer"},
		{"no message", `{"kind": "start", "format": 1}` + "\n" + `{"kind": "end"}`, "the capture holds no CMP, EST or SCEP message"},
		{"bad message line", string(captureLines(t,
			map[string]any{"kind": "start", "format": 1},
			map[string]any{"kind": "request", "body": "genm", "der": []byte{0x30, 0x00}},
		)), "f:2: not a CMP message"},
		{"pem certificate", string(certPEM), "f: PEM block 1 (CERTIFICATE): not a CMP message"},
		{"pem without block", "-----BEGIN broken", "f: no PEM block"},
		{"der", string(genm[:len(genm)-1]), "f: not a CMP message"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("f", []byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %v, want %q", err, tt.want)
			}
		})
	}
}

// TestRead checks reading a file and standard input.
func TestRead(t *testing.T) {
	genm := encode(t, pkicmp.NewGenMBody())
	path := filepath.Join(t.TempDir(), "genm.der")
	if err := os.WriteFile(path, genm, 0o600); err != nil {
		t.Fatal(err)
	}
	if msgs, err := Read(path, nil); err != nil || len(msgs) != 1 || msgs[0].Source != path {
		t.Errorf("Read(file) = %v, %v", msgs, err)
	}
	if msgs, err := Read("-", strings.NewReader(base64.StdEncoding.EncodeToString(genm))); err != nil || msgs[0].Source != "standard input" {
		t.Errorf("Read(-) = %v, %v", msgs, err)
	}
	if _, err := Read(filepath.Join(t.TempDir(), "missing"), nil); !os.IsNotExist(err) {
		t.Errorf("Read(missing) error = %v", err)
	}
}
