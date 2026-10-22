// Package secret obtains shared secrets and passwords without taking them from the command line,
// where other users could read them from the process list.
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// EnvVar is the environment variable that can hold the shared secret.
const EnvVar = "CERTRALLY_SECRET"

// PasswordEnvVar is the environment variable that can hold the password.
const PasswordEnvVar = "CERTRALLY_PASSWORD" //nolint:gosec // G101: the name of a variable, not a password.

// maxSize bounds how much is read from a secret file or standard input.
const maxSize = 64 * 1024

// Kind names a secret and the variable and flag that supply it.
type Kind struct {
	// Name is how messages and the prompt call the secret.
	Name string
	// EnvVar is the environment variable that can hold the secret.
	EnvVar string
	// Flag is the option that names a file holding the secret.
	Flag string
}

// The kinds of secret certrally reads.
var (
	// SharedSecret protects CMP requests with a MAC.
	SharedSecret = Kind{Name: "shared secret", EnvVar: EnvVar, Flag: "--secret-file"}
	// Password signs in to an EST server with HTTP Basic authentication or TLS-SRP.
	Password = Kind{Name: "password", EnvVar: PasswordEnvVar, Flag: "--password-file"}
)

// Source says where the secret may come from. The first available source wins: File, then the
// variable of Kind, then a prompt when Stdin is a terminal.
type Source struct {
	// Kind is the secret to read. The zero value reads the shared secret.
	Kind Kind
	// File is a path to read the secret from, or "-" for standard input.
	File string
	// LookupEnv reads an environment variable, normally os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// Stdin is read for File "-" and prompted on when it is a terminal.
	Stdin io.Reader
	// Prompt receives the prompt text, normally standard error.
	Prompt io.Writer
}

// ErrMissing reports that no source provided a secret. The errors Read returns for it wrap it.
var ErrMissing = errors.New("no secret")

// missingError names the sources of a secret that none of them provided.
type missingError struct{ kind Kind }

// Error says how to provide the secret.
func (e *missingError) Error() string {
	return "no " + e.kind.Name + ": use " + e.kind.Flag + ", set " + e.kind.EnvVar + " or run on a terminal to be prompted"
}

// Is matches ErrMissing.
func (e *missingError) Is(target error) bool { return target == ErrMissing }

// Read returns the secret with one trailing line ending removed. An empty secret is an error.
func (s Source) Read() ([]byte, error) {
	if s.Kind == (Kind{}) {
		s.Kind = SharedSecret
	}
	secret, err := s.read()
	if err != nil {
		return nil, err
	}
	secret = trimLineEnding(secret)
	if len(secret) == 0 {
		return nil, fmt.Errorf("the %s is empty", s.Kind.Name)
	}
	return secret, nil
}

// read returns the raw secret from the first available source.
func (s Source) read() ([]byte, error) {
	switch {
	case s.File == "-":
		return s.readLimited(s.Stdin, "standard input")
	case s.File != "":
		f, err := os.Open(s.File)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return s.readLimited(f, s.File)
	}
	if s.LookupEnv != nil {
		if v, ok := s.LookupEnv(s.Kind.EnvVar); ok {
			return []byte(v), nil
		}
	}
	f, ok := s.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, &missingError{kind: s.Kind}
	}
	_, _ = fmt.Fprint(s.Prompt, strings.ToUpper(s.Kind.Name[:1])+s.Kind.Name[1:]+": ")
	secret, err := term.ReadPassword(int(f.Fd()))
	_, _ = fmt.Fprintln(s.Prompt)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.Kind.Name, err)
	}
	return secret, nil
}

// readLimited reads r up to maxSize bytes and fails if there is more.
func (s Source) readLimited(r io.Reader, name string) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("read %s from %s: no input", s.Kind.Name, name)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s from %s: %w", s.Kind.Name, name, err)
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("%s in %s is longer than %d bytes", s.Kind.Name, name, maxSize)
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
