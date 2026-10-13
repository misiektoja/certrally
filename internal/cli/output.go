package cli

import (
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"

	"github.com/charmbracelet/colorprofile"

	"github.com/misiektoja/certrally/internal/pemfile"
)

// stdoutPath is the output path that means standard output.
const stdoutPath = "-"

// Report field names that several commands share.
const (
	fieldSaved   = "Saved"
	fieldNote    = "Note"
	fieldSubject = "Subject"
	fieldIssuer  = "Issuer"
	fieldKey     = "Key"
)

// writeData writes data to path, or to stdout when path is "-".
func writeData(path string, data []byte, perm fs.FileMode, force bool, stdout io.Writer) error {
	if path == stdoutPath {
		_, err := stdout.Write(data)
		return err
	}
	return pemfile.Write(path, data, perm, force)
}

// reportWriter returns where the human-readable report goes: standard output, unless one of the
// outputs already writes data there.
func reportWriter(stdout, stderr io.Writer, outputs ...string) io.Writer {
	w := stdout
	if slices.Contains(outputs, stdoutPath) {
		w = stderr
	}
	return colorprofile.NewWriter(w, os.Environ())
}

// count returns n followed by the singular or plural noun.
func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}

// savedPaths lists the outputs written to files, for the report.
func savedPaths(outputs ...string) []string {
	var saved []string
	for _, p := range outputs {
		if p != "" && p != stdoutPath {
			saved = append(saved, p)
		}
	}
	return saved
}
