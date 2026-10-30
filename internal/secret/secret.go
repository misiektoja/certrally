// Package secret obtains shared secrets, passwords and tokens from a command-line value, a file, an
// environment variable or a prompt. Other users can read a command-line value from the process
// list, so the other sources suit shared machines better.
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

// KeyPasswordEnvVar is the environment variable that can hold the password of an encrypted private
// key file.
const KeyPasswordEnvVar = "CERTRALLY_KEY_PASSWORD" //nolint:gosec // G101: the name of a variable, not a password.

// TokenEnvVar is the environment variable that can hold the bearer token.
const TokenEnvVar = "CERTRALLY_TOKEN" //nolint:gosec // G101: the name of a variable, not a token.

// ChallengeEnvVar names the environment variable that holds a SCEP challenge password.
const ChallengeEnvVar = "CERTRALLY_CHALLENGE"

// maxSize bounds how much is read from a secret file or standard input.
const maxSize = 64 * 1024

// Kind names a secret and the variable and flags that supply it.
type Kind struct {
	// Name is how messages and the prompt call the secret.
	Name string
	// EnvVar is the environment variable that can hold the secret.
	EnvVar string
	// Flag is the option that takes the secret on the command line, as messages show it.
	Flag string
	// FileFlag is the option that names a file holding the secret.
	FileFlag string
}

// The kinds of secret certrally reads.
var (
	// SharedSecret protects CMP requests with a MAC.
	SharedSecret = Kind{Name: "shared secret", EnvVar: EnvVar, Flag: "--secret", FileFlag: "--secret-file"}
	// Password signs in to an EST server with HTTP Basic authentication or TLS-SRP.
	Password = Kind{Name: "password", EnvVar: PasswordEnvVar, Flag: "--password", FileFlag: "--password-file"}
	// KeyPassword decrypts an encrypted private key file.
	KeyPassword = Kind{
		Name:     "key password",
		EnvVar:   KeyPasswordEnvVar,
		Flag:     "--key-password",
		FileFlag: "--key-password-file",
	}
	// Token signs in to an EST server with HTTP Bearer authentication. A bare --token selects the
	// sign-in, so the value needs the = form.
	Token = Kind{Name: "token", EnvVar: TokenEnvVar, Flag: "--token=TOKEN", FileFlag: "--token-file"}
	// Challenge authorizes a SCEP enrollment as the challengePassword of the request.
	Challenge = Kind{
		Name:     "challenge password",
		EnvVar:   ChallengeEnvVar,
		Flag:     "--challenge",
		FileFlag: "--challenge-file",
	}
)

// Value is a flag that takes a secret on the command line. String never returns the secret, so
// help, completion and printed command lines cannot show it.
type Value struct {
	secret []byte
}

// Set stores the secret and refuses an empty one.
func (v *Value) Set(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	v.secret = []byte(s)
	return nil
}

// String returns "" so that nothing prints the secret.
func (v *Value) String() string { return "" }

// Type names the kind of value in help.
func (v *Value) Type() string { return "string" }

// Bytes returns the secret, or nil when the flag was not given.
func (v *Value) Bytes() []byte { return v.secret }

// Source says where the secret may come from. The first available source wins: Value, then File,
// then the variable of Kind, then a prompt when Stdin is a terminal.
type Source struct {
	// Kind is the secret to read. The zero value reads the shared secret.
	Kind Kind
	// Value is the secret given on the command line, nil when there is none.
	Value []byte
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
	return "no " + e.kind.Name + ": use " + e.kind.Flag + " or " + e.kind.FileFlag + ", set " + e.kind.EnvVar +
		" or run on a terminal to be prompted"
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
	case s.Value != nil:
		return bytes.Clone(s.Value), nil
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
