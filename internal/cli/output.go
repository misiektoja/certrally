package cli

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/colorprofile"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
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

// outputOptions holds the flags that choose how a command reports its outcome.
type outputOptions struct {
	quiet bool
	json  bool
}

// addFlags registers --quiet and --json.
func (o *outputOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVarP(&o.quiet, "quiet", "q", false, "print only warnings and errors")
	f.BoolVar(&o.json, "json", false, "print the outcome as one JSON document on standard output")
	cmd.MarkFlagsMutuallyExclusive("quiet", "json")
}

// checkStdout rejects data written to standard output together with --json, since both would
// share it.
func (o *outputOptions) checkStdout(paths ...string) error {
	for _, p := range paths {
		if p == stdoutPath && o.json {
			return errors.New("--json writes to standard output, so an output cannot be -")
		}
	}
	return nil
}

// jsonDocument is the --json output. Its fields are documented in docs/json.md and must stay
// compatible.
type jsonDocument struct {
	Command    string         `json:"command"`
	OK         bool           `json:"ok"`
	ExitStatus int            `json:"exitStatus"`
	Server     string         `json:"server,omitempty"`
	Exchange   []trace.Record `json:"exchange,omitempty"`
	Result     any            `json:"result,omitempty"`
	Error      *failure       `json:"error,omitempty"`
	Warnings   []string       `json:"warnings,omitempty"`
}

// printer reports the outcome of a command, as text or as one JSON document.
type printer struct {
	opts    outputOptions
	command string
	stdout  io.Writer
	stderr  io.Writer
	// dataOnStdout is set when the command writes data such as a certificate to standard output.
	// The text report then goes to standard error.
	dataOnStdout bool
	// session is the connection the command opened, if any.
	session *session
	doc     jsonDocument
}

// newPrinter returns the printer for a command.
func newPrinter(cmd *cobra.Command, opts outputOptions) *printer {
	return &printer{
		opts:    opts,
		command: commandName(cmd),
		stdout:  cmd.OutOrStdout(),
		stderr:  colorprofile.NewWriter(cmd.ErrOrStderr(), os.Environ()),
	}
}

// commandName returns the command path without the program name, such as "cmp genm crl".
func commandName(cmd *cobra.Command) string {
	return strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()+" ")
}

// runWith returns a cobra run function that gives run a printer and finishes the output.
func runWith(opts *outputOptions, run func(cmd *cobra.Command, args []string, p *printer) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		p := newPrinter(cmd, *opts)
		return p.finish(run(cmd, args, p))
	}
}

// text reports whether the outcome is printed as text.
func (p *printer) text() bool { return !p.opts.json }

// showProgress reports whether the ladder and the success report are printed.
func (p *printer) showProgress() bool { return p.text() && !p.opts.quiet }

// reportWriter returns where the text report goes.
func (p *printer) reportWriter() io.Writer {
	if p.dataOnStdout {
		return p.stderr
	}
	return colorprofile.NewWriter(p.stdout, os.Environ())
}

// result reports success: the title and fields as text or result in the JSON document.
func (p *printer) result(title string, fields []ui.Field, result any) {
	p.doc.Result = result
	if p.showProgress() {
		ui.Report(p.reportWriter(), true, title, fields)
	}
}

// section adds a section below the text report.
func (p *printer) section(heading string, fields []ui.Field) {
	if p.showProgress() {
		ui.Section(p.reportWriter(), heading, fields)
	}
}

// line writes a progress line, such as one ping reply.
func (p *printer) line(text string) {
	if p.showProgress() {
		_, _ = io.WriteString(p.reportWriter(), text+"\n")
	}
}

// warn reports a problem that does not fail the command.
func (p *printer) warn(text string) {
	p.doc.Warnings = append(p.doc.Warnings, text)
	if p.text() {
		ui.Warning(p.stderr, text)
	}
}

// fail reports a failure and returns the error that carries its exit status. fields replace the
// text form of f when they are given.
func (p *printer) fail(f *failure, err error, fields ...ui.Field) error {
	p.doc.Error = f
	if p.text() {
		if fields == nil {
			fields = f.fields(p.session)
		}
		ui.Report(p.stderr, false, f.Title, fields)
	}
	return &exitError{code: f.code, err: err}
}

// finish completes the output of a command that returned err: it closes the capture and writes
// the JSON document. It returns the error that sets the exit status.
func (p *printer) finish(err error) error {
	code := exitOK
	if err != nil {
		code = exitLocal
		if ee, ok := errors.AsType[*exitError](err); ok {
			code = ee.code
		}
	}
	if s := p.session; s != nil && s.capture != nil {
		if cerr := s.capture.Close(code); cerr != nil {
			p.warn("The capture file is incomplete: " + cerr.Error())
		}
	}
	if p.text() {
		return err
	}

	if err != nil && p.doc.Error == nil {
		p.doc.Error = &failure{code: code, Title: "The command failed", Message: err.Error()}
	}
	p.doc.Command, p.doc.OK, p.doc.ExitStatus = p.command, code == exitOK, code
	if s := p.session; s != nil {
		p.doc.Server = s.conn.redactedServer()
		events := s.recorder.Events()
		p.doc.Exchange = make([]trace.Record, 0, len(events))
		for _, ev := range events {
			p.doc.Exchange = append(p.doc.Exchange, ev.Record(false))
		}
	}
	if werr := writeJSON(p.stdout, p.doc); werr != nil && err == nil {
		return werr
	}
	if err != nil && code == exitLocal {
		// The JSON document already holds the error, so it is not printed again.
		return &exitError{code: exitLocal, err: err}
	}
	return err
}

// writeJSON writes v as indented JSON.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeData writes data to path. A path of "-" writes to stdout.
func writeData(path string, data []byte, perm fs.FileMode, force bool, stdout io.Writer) error {
	if path == stdoutPath {
		_, err := stdout.Write(data)
		return err
	}
	return pemfile.Write(path, data, perm, force)
}

// count returns n followed by the singular or plural noun.
func count(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}

// savedPaths lists the outputs written to files.
func savedPaths(outputs ...string) []string {
	saved := []string{}
	for _, p := range outputs {
		if p != "" && p != stdoutPath {
			saved = append(saved, p)
		}
	}
	return saved
}
