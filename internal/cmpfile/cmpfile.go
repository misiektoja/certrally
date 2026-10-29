// Package cmpfile reads CMP, EST and SCEP messages from capture files and from files that hold one message
// as DER, PEM, base64 or hex.
package cmpfile

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/asn1"
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
	est "github.com/misiektoja/go-pki-est"
	"go.mozilla.org/pkcs7"

	"github.com/misiektoja/certrally/internal/trace"
)

// Message is a CMP, EST or SCEP message read from a file.
type Message struct {
	// Source locates the message, such as "run.jsonl:4" for line 4 of a capture file or "ip.der".
	Source string
	// File is the name the message was read from.
	File string
	// Run numbers the capture run that holds the message, starting at 1. It is 0 for other files.
	Run int
	// Request reports whether the client sent the message. A capture records it. For other files
	// it follows from the body type or EST content.
	Request bool
	// Time is when the capture recorded the message. It is zero for other files.
	Time time.Time
	// Server is the server of the capture run.
	Server string
	// DER is the message. For an EST serverkeygen response it is the certificate part. It is empty
	// for an EST exchange without a body, such as a cacerts request or an error response.
	DER []byte
	// Msg is the CMP message. It is nil for an EST message.
	Msg *pkicmp.PKIMessage
	// EST describes an EST message. A capture records the HTTP exchange. For other files only Kind
	// and Content are set. It is nil for a CMP message.
	EST *trace.Record
	// SCEP describes a SCEP message, which only a capture records. DER then holds the pkiMessage of
	// a request and the body of a response.
	SCEP *trace.Record
}

// Kinds of capture lines that hold a message.
const (
	kindRequest  = "request"
	kindResponse = "response"
)

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
		return nil, fmt.Errorf("%s: not a capture file and not a CMP or EST message as DER, PEM, base64 or hex", name)
	}
	return single(name, der)
}

// single returns the one message in der.
func single(name string, der []byte) ([]Message, error) {
	m, err := parseAny(name, name, der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return []Message{m}, nil
}

// parseAny parses der as a CMP message or, failing that, as an EST message.
func parseAny(source, name string, der []byte) (Message, error) {
	msg, err := parseMessage(der)
	if err == nil {
		return fileMessage(source, name, der, msg), nil
	}
	if content := estContent(der); content != "" {
		return estFileMessage(source, name, der, content), nil
	}
	return Message{}, fmt.Errorf("%w, and not a PKCS#10 request, certs-only message or CSR attributes of EST", err)
}

// fileMessage returns a CMP message read from a file other than a capture.
func fileMessage(source, name string, der []byte, msg *pkicmp.PKIMessage) Message {
	return Message{Source: source, File: name, Request: IsRequest(msg.Body.Type), DER: der, Msg: msg}
}

// estFileMessage returns an EST message read from a file other than a capture. Only a PKCS#10
// request is sent by the client.
func estFileMessage(source, name string, der []byte, content string) Message {
	kind := kindResponse
	if content == trace.ContentPKCS10 {
		kind = kindRequest
	}
	return Message{
		Source:  source,
		File:    name,
		Request: kind == kindRequest,
		DER:     der,
		EST:     &trace.Record{Kind: kind, Content: content, Size: len(der)},
	}
}

// estContent names the EST message in der: trace.ContentPKCS10, trace.ContentCertsOnly or
// trace.ContentCSRAttrs. It returns "" when der is none of them.
func estContent(der []byte) string {
	if _, err := x509.ParseCertificateRequest(der); err == nil {
		return trace.ContentPKCS10
	}
	if _, err := pkcs7.Parse(der); err == nil {
		return trace.ContentCertsOnly
	}
	if isCSRAttrs(der) {
		return trace.ContentCSRAttrs
	}
	return ""
}

// isCSRAttrs reports whether der holds CSR attributes (RFC 7030 section 4.5.2) with at least one
// entry. est.CSRAttrs skips entries that are neither an OID nor an attribute, so it would accept
// any SEQUENCE.
func isCSRAttrs(der []byte) bool {
	var seq []asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) > 0 || len(seq) == 0 {
		return false
	}
	for _, item := range seq {
		if item.Class != asn1.ClassUniversal || item.Tag != asn1.TagOID && item.Tag != asn1.TagSequence {
			return false
		}
	}
	var attrs est.CSRAttrs
	return attrs.Unmarshal(der) == nil
}

// pemContents are the EST contents of PEM block types. Other types are tried as CMP and then EST.
var pemContents = map[string]string{
	"CERTIFICATE REQUEST":     trace.ContentPKCS10,
	"NEW CERTIFICATE REQUEST": trace.ContentPKCS10,
	"PKCS7":                   trace.ContentCertsOnly,
	"CMS":                     trace.ContentCertsOnly,
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

// parsePEM returns the message in each PEM block. A block of a type in pemContents must hold that
// EST content. Other types are not checked, because no type is registered for CMP messages.
func parsePEM(name string, data []byte) ([]Message, error) {
	var msgs []Message
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		source := fmt.Sprintf("%s#%d", name, len(msgs)+1)
		if content, ok := pemContents[block.Type]; ok {
			if estContent(block.Bytes) != content {
				return nil, fmt.Errorf("%s: PEM block %d (%s) does not decode", name, len(msgs)+1, block.Type)
			}
			msgs = append(msgs, estFileMessage(source, name, block.Bytes, content))
			continue
		}
		m, err := parseAny(source, name, block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: PEM block %d (%s): %w", name, len(msgs)+1, block.Type, err)
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("%s: no PEM block", name)
	}
	return msgs, nil
}

// captureLine holds the fields of a capture line that Parse uses. The capture package documents the
// format.
type captureLine struct {
	Kind     string    `json:"kind"`
	Format   int       `json:"format"`
	Protocol string    `json:"protocol"`
	Server   string    `json:"server"`
	Time     time.Time `json:"time"`
	Body     string    `json:"body"`
	DER      []byte    `json:"der"`
}

// Protocols of a capture run besides CMP, as the start line names them.
const (
	protocolEST  = "est"
	protocolSCEP = "scep"
)

// captureFormat is the newest capture format Parse understands.
const captureFormat = 1

// parseCapture returns the messages of every run in a capture file. In a CMP run, requests without
// a response, failures and responses that are not CMP messages, such as an HTML error page, are
// skipped. In an EST or SCEP run every request and response is kept, because the HTTP exchange is
// the message even without a body. Connections and failures are skipped.
func parseCapture(name string, data []byte) ([]Message, error) {
	var msgs []Message
	run, server, protocol := 0, "", ""
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
			run, server, protocol = run+1, line.Server, line.Protocol
		case kindRequest, kindResponse:
			if protocol == protocolEST || protocol == protocolSCEP {
				var rec trace.Record
				if err := json.Unmarshal(text, &rec); err != nil {
					return nil, fmt.Errorf("%s:%d: not a capture line: %w", name, n, err)
				}
				m := Message{
					Source:  fmt.Sprintf("%s:%d", name, n),
					File:    name,
					Run:     max(run, 1),
					Request: line.Kind == kindRequest,
					Time:    line.Time,
					Server:  server,
					DER:     rec.DER,
				}
				if protocol == protocolSCEP {
					m.SCEP = &rec
				} else {
					m.EST = &rec
				}
				msgs = append(msgs, m)
				continue
			}
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
				Request: line.Kind == kindRequest,
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
		return nil, fmt.Errorf("%s: the capture holds no CMP, EST or SCEP message", name)
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
