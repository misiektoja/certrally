// Package termcolor decides when certrally colours its output.
//
// Colour detection is done by github.com/charmbracelet/colorprofile, which reads the process
// environment. This package rewrites the colour variables in that environment, so the --color flag,
// NO_COLOR and FORCE_COLOR apply equally to every writer. That includes the help and error output that
// fang renders before any certrally code runs.
package termcolor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Mode is a value of the --color flag.
type Mode string

const (
	// Auto colours output written to a terminal unless the environment disables it.
	Auto Mode = "auto"
	// Always colours output even when it is not written to a terminal.
	Always Mode = "always"
	// Never writes no colour. Text attributes such as bold remain on a terminal, as with NO_COLOR.
	Never Mode = "never"
)

// Modes lists the accepted modes in the order help and shell completion show them.
var Modes = []Mode{Auto, Always, Never}

// Environment variables that colour detection reads.
const (
	noColor       = "NO_COLOR"
	forceColor    = "FORCE_COLOR"
	cliColorForce = "CLICOLOR_FORCE"
)

// ParseMode returns the mode named by s.
func ParseMode(s string) (Mode, error) {
	for _, m := range Modes {
		if s == string(m) {
			return m, nil
		}
	}
	return "", fmt.Errorf("invalid color mode %q, want auto, always or never", s)
}

// Environ returns a copy of env in which colorprofile's detection follows mode.
//
// Precedence, highest first: an explicit Always or Never, then NO_COLOR, then FORCE_COLOR and
// CLICOLOR_FORCE, then terminal detection. NO_COLOR disables colour whenever it is non-empty, as
// no-color.org specifies, although colorprofile honours only boolean values and lets CLICOLOR_FORCE
// win when output is not a terminal. FORCE_COLOR forces colour unless it is 0 or false. colorprofile
// does not read FORCE_COLOR, so it is mapped to CLICOLOR_FORCE.
func Environ(mode Mode, env []string) []string {
	var noColorSet, forced bool
	out := make([]string, 0, len(env)+1)
	// NO_COLOR and CLICOLOR_FORCE are rewritten below. FORCE_COLOR stays for other programs unless
	// colour is disabled.
	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		switch key {
		case noColor:
			noColorSet = value != ""
			continue
		case cliColorForce:
			on, _ := strconv.ParseBool(value)
			forced = forced || on
			continue
		case forceColor:
			forced = forced || forceColorEnabled(value)
		}
		out = append(out, kv)
	}

	switch {
	case mode == Never, mode != Always && noColorSet:
		out = withoutKey(out, forceColor)
		out = append(out, noColor+"=1")
	case mode == Always, forced:
		out = append(out, cliColorForce+"=1")
	}
	return out
}

// Apply rewrites the colour variables of the process environment so that detection follows mode.
func Apply(mode Mode) error {
	want := Environ(mode, os.Environ())
	values := make(map[string]string, 3)
	for _, kv := range want {
		key, value, _ := strings.Cut(kv, "=")
		if key == noColor || key == forceColor || key == cliColorForce {
			values[key] = value
		}
	}
	for _, key := range []string{noColor, forceColor, cliColorForce} {
		value, ok := values[key]
		var err error
		if ok {
			err = os.Setenv(key, value)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			return fmt.Errorf("set %s: %w", key, err)
		}
	}
	return nil
}

// forceColorEnabled reports whether a FORCE_COLOR value asks for colour. Node.js and chalk treat 0
// and false as a request for no colour, so those values do not force it here either.
func forceColorEnabled(value string) bool {
	return value != "" && value != "0" && !strings.EqualFold(value, "false")
}

// withoutKey returns env without the entries for key.
func withoutKey(env []string, key string) []string {
	out := env[:0]
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k != key {
			out = append(out, kv)
		}
	}
	return out
}
