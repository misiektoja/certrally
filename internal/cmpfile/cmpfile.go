// Package cmpfile reads CMP messages from capture files and from files that hold one message as DER,
// PEM, base64 or hex.
package cmpfile

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// Message is a CMP message read from a file.
type Message struct {
	// Source locates the message, such as "run.jsonl:4" for line 4 of a capture file or "ip.der".
	Source string
	// File is the name the message was read from.
	File string
	// Run numbers the capture run that holds the message, starting at 1. It is 0 for other files.
	Run int
	// Request reports whether the client sent the message. A capture records it. For other files
	// it follows from the body type.
	Request bool
	// Time is when the capture recorded the message. It is zero for other files.
	Time time.Time
	// Server is the server of the capture run.
	Server string
	DER    []byte
	Msg    *pkicmp.PKIMessage
}

// maxFileSize bounds what Read loads, well above a capture of many runs.
const maxFileSize = 256 << 20

// Read reads the messages in the file at path. A path of "-" reads stdin.
func Read(path string, stdin io.Reader) ([]Message, error) {
	var r io.Reader
	name := path
	if path == "-" {
		r, name = stdin, "standard input"
	} else {
		f, err := os.Open(path) //nolint:gosec // G304: the user names the file.
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s: larger than %d MiB", name, maxFileSize>>20)
	}
	return Parse(name, data)
}

// Parse returns the messages in data, which was read from the file name. It accepts a capture file,
// PEM blocks that each hold a message and a single message as DER, base64 or hex. It returns at
// least one message or an error.
func Parse(name string, data []byte) ([]Message, error) {
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(trimmed) == 0:
		return nil, fmt.Errorf("%s: the file is empty", name)
	case trimmed[0] == '{':
		return parseCapture(name, data)
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN ")):
		return parsePEM(name, data)
	case data[0] == 0x30:
		return single(name, data)
	}
	// Ordinary text can decode as base64, so only a decoded SEQUENCE counts as a message.
	der, err := decodeText(trimmed)
	if err != nil || len(der) == 0 || der[0] != 0x30 {
		return nil, fmt.Errorf("%s: not a capture file and not a CMP message as DER, PEM, base64 or hex", name)
	}
	return single(name, der)
}

// single returns the one message in der.
func single(name string, der []byte) ([]Message, error) {
	msg, err := parseMessage(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return []Message{fileMessage(name, name, der, msg)}, nil
}

// fileMessage returns a message read from a file other than a capture.
func fileMessage(source, name string, der []byte, msg *pkicmp.PKIMessage) Message {
	return Message{Source: source, File: name, Request: IsRequest(msg.Body.Type), DER: der, Msg: msg}
}

// parseMessage parses der as a PKIMessage with a body.
func parseMessage(der []byte) (*pkicmp.PKIMessage, error) {
	msg, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		return nil, fmt.Errorf("not a CMP message: %w", err)
	}
	if msg.Body == nil {
		return nil, errors.New("not a CMP message: no body")
	}
	return msg, nil
}

// decodeText decodes a message written as hex, with optional colons and white space, or as base64.
func decodeText(text []byte) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if r == ':' || r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, string(text))
	if der, err := hex.DecodeString(compact); err == nil {
		return der, nil
	}
	compact = strings.Join(strings.Fields(string(text)), "")
	encodings := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		if der, err := enc.DecodeString(compact); err == nil {
			return der, nil
		}
	}
	return nil, errors.New("neither hex nor base64")
}

// parsePEM returns the message in each PEM block. The block type is not checked, because no type is
// registered for CMP messages.
func parsePEM(name string, data []byte) ([]Message, error) {
	var msgs []Message
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		source := fmt.Sprintf("%s#%d", name, len(msgs)+1)
		msg, err := parseMessage(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: PEM block %d (%s): %w", name, len(msgs)+1, block.Type, err)
		}
		msgs = append(msgs, fileMessage(source, name, block.Bytes, msg))
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("%s: no PEM block", name)
	}
	return msgs, nil
}

// captureLine holds the fields of a capture line that Parse uses. The capture package documents the
// format.
type captureLine struct {
	Kind   string    `json:"kind"`
	Format int       `json:"format"`
	Server string    `json:"server"`
	Time   time.Time `json:"time"`
	Body   string    `json:"body"`
	DER    []byte    `json:"der"`
}

// captureFormat is the newest capture format Parse understands.
const captureFormat = 1

// parseCapture returns the messages of every run in a capture file. Requests without a response,
// failures and responses that are not CMP messages, such as an HTML error page, are skipped.
func parseCapture(name string, data []byte) ([]Message, error) {
	var msgs []Message
	run, server := 0, ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxFileSize)
	for n := 1; sc.Scan(); n++ {
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		var line captureLine
		if err := json.Unmarshal(text, &line); err != nil {
			if n == 1 && string(text) == "{" {
				return nil, fmt.Errorf("%s: not a capture file. --json output has no message bytes, "+
					"so record the run with --capture", name)
			}
			return nil, fmt.Errorf("%s:%d: not a capture line: %w", name, n, err)
		}
		switch line.Kind {
		case "start":
			if line.Format > captureFormat {
				return nil, fmt.Errorf("%s:%d: capture format %d is newer than this certrally understands", name, n, line.Format)
			}
			run, server = run+1, line.Server
		case "request", "response":
			if len(line.DER) == 0 || line.Body == "" {
				continue
			}
			msg, err := parseMessage(line.DER)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, n, err)
			}
			msgs = append(msgs, Message{
				Source:  fmt.Sprintf("%s:%d", name, n),
				File:    name,
				Run:     max(run, 1),
				Request: line.Kind == "request",
				Time:    line.Time,
				Server:  server,
				DER:     line.DER,
				Msg:     msg,
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if run == 0 {
		return nil, fmt.Errorf("%s: not a capture file, it has no start line", name)
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("%s: the capture holds no CMP message", name)
	}
	return msgs, nil
}

// IsRequest reports whether a client sends messages with this body type.
func IsRequest(t pkicmp.BodyType) bool {
	switch t {
	case pkicmp.BodyTypeIR, pkicmp.BodyTypeCR, pkicmp.BodyTypeKUR, pkicmp.BodyTypeP10CR, pkicmp.BodyTypeRR,
		pkicmp.BodyTypeCertConf, pkicmp.BodyTypePollReq, pkicmp.BodyTypeGenM, pkicmp.BodyTypePopDecR:
		return true
	default:
		return false
	}
}
