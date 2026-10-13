// Package secret obtains the shared secret for MAC-protected requests without taking it from the
// command line, where other users could read it from the process list.
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// EnvVar is the environment variable that can hold the shared secret.
const EnvVar = "CERTRALLY_SECRET"

// maxSize bounds how much is read from a secret file or standard input.
const maxSize = 64 * 1024

// Source says where the secret may come from. The first available source wins: File, then the
// EnvVar variable, then a prompt when Stdin is a terminal.
type Source struct {
	// File is a path to read the secret from, or "-" for standard input.
	File string
	// LookupEnv reads an environment variable, normally os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Stdin is read for File "-" and prompted on when it is a terminal.
	Stdin io.Reader
	// Prompt receives the prompt text, normally standard error.
	Prompt io.Writer
}

// ErrMissing reports that no source provided a secret.
var ErrMissing = errors.New("no shared secret: use --secret-file, set " + EnvVar +
	" or run on a terminal to be prompted")

// Read returns the secret with one trailing line ending removed. An empty secret is an error.
func (s Source) Read() ([]byte, error) {
	secret, err := s.read()
	if err != nil {
		return nil, err
	}
	secret = trimLineEnding(secret)
	if len(secret) == 0 {
		return nil, errors.New("the shared secret is empty")
	}
	return secret, nil
}

// read returns the raw secret from the first available source.
func (s Source) read() ([]byte, error) {
	switch {
	case s.File == "-":
		return readLimited(s.Stdin, "standard input")
	case s.File != "":
		f, err := os.Open(s.File)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return readLimited(f, s.File)
	}
	if s.LookupEnv != nil {
		if v, ok := s.LookupEnv(EnvVar); ok {
			return []byte(v), nil
		}
	}
	f, ok := s.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, ErrMissing
	}
	_, _ = fmt.Fprint(s.Prompt, "Shared secret: ")
	secret, err := term.ReadPassword(int(f.Fd()))
	_, _ = fmt.Fprintln(s.Prompt)
	if err != nil {
		return nil, fmt.Errorf("read shared secret: %w", err)
	}
	return secret, nil
}

// readLimited reads r up to maxSize bytes and fails if there is more.
func readLimited(r io.Reader, name string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("read shared secret from %s: no input", name)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read shared secret from %s: %w", name, err)
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("shared secret in %s is longer than %d bytes", name, maxSize)
	}
	return data, nil
}

// trimLineEnding removes one trailing "\n" or "\r\n", which editors and echo add to files.
func trimLineEnding(b []byte) []byte {
	if rest, ok := bytes.CutSuffix(b, []byte("\n")); ok {
		b, _ = bytes.CutSuffix(rest, []byte("\r"))
	}
	return b
}
