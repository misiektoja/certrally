package cli

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"charm.land/huh/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/ui"
)

// errEnrollCancelled reports that the user stopped the wizard or declined to send the request.
var errEnrollCancelled = errors.New("enrollment cancelled, nothing was sent")

// wizardTerminal reports whether the wizard can read answers from in and draw on out. Tests
// replace it.
var wizardTerminal = func(in io.Reader, out io.Writer) bool {
	return isTerminal(in) && isTerminal(out)
}

// isTerminal reports whether v is a file open on a terminal.
func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// newAsker returns what asks the wizard's questions. Tests replace it.
var newAsker = func(ctx context.Context, in io.Reader, out io.Writer) asker {
	width := terminalWidth(out)
	return &formAsker{
		ctx:   ctx,
		in:    in,
		out:   out,
		shown: colorprofile.NewWriter(out, os.Environ()),
		width: min(width, formWidth),
		// ACCESSIBLE is the variable huh programs read to ask line by line, for screen readers. A
		// terminal too narrow to draw a form gets the same questions.
		accessible: os.Getenv("ACCESSIBLE") != "" || width < minFormWidth,
	}
}

// Form widths. Short lines read better, and huh cannot lay out fields narrower than the minimum.
const (
	formWidth    = 80
	minFormWidth = 40
)

// terminalWidth returns the width of the terminal that w writes to, or 0 when it is unknown.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return width
}

// question is a question with a typed answer.
type question struct {
	title       string
	description string
	placeholder string
	// value is the answer the field starts with.
	value string
	// empty describes an empty answer when it is shown.
	empty string
	// hidden hides the answer while it is typed and when it is shown.
	hidden   bool
	validate func(string) error
}

// choice is one answer to a multiple-choice question.
type choice struct {
	label string
	value string
}

// asker asks the wizard's questions.
type asker interface {
	// input asks for a line of text.
	input(q question) (string, error)
	// choose asks for one of choices and returns its value. value is preselected.
	choose(title, description string, choices []choice, value string) (string, error)
	// confirm asks a yes or no question.
	confirm(title string, value bool) (bool, error)
	// show lists an answer that the command line already gave.
	show(title, value string)
}

// formAsker asks each question with its own huh form and leaves a line with the answer.
type formAsker struct {
	ctx context.Context
	in  io.Reader
	// out is the terminal the forms draw on. shown writes the answer lines to it.
	out   io.Writer
	shown io.Writer
	// width is the width of the forms. huh sizes the fields from the terminal unless the form has a
	// width.
	width      int
	accessible bool
}

// run asks the question in field.
func (a *formAsker) run(field huh.Field) error {
	out := a.out
	if a.accessible {
		// Accessible forms write styled text without checking the terminal.
		out = a.shown
	}
	err := huh.NewForm(huh.NewGroup(field)).
		WithInput(a.in).
		WithOutput(out).
		WithAccessible(a.accessible).
		WithWidth(a.width).
		RunWithContext(a.ctx)
	if errors.Is(err, huh.ErrUserAborted) {
		return errEnrollCancelled
	}
	return err
}

// answered shows an answer unless the accessible form has left it on the screen already.
func (a *formAsker) answered(title, value string) {
	if !a.accessible {
		a.show(title, value)
	}
}

// explain writes the description of a question in accessible mode, which shows only titles.
func (a *formAsker) explain(description, value string) {
	if !a.accessible {
		return
	}
	if description != "" {
		_, _ = fmt.Fprintln(a.shown, description)
	}
	if value != "" {
		_, _ = fmt.Fprintf(a.shown, "Press Enter for %s.\n", value)
	}
}

// input asks q with a text field.
func (a *formAsker) input(q question) (string, error) {
	a.explain(q.description, q.value)
	value := q.value
	field := huh.NewInput().Title(q.title).Description(q.description).Placeholder(q.placeholder).Value(&value)
	if q.validate != nil {
		field = field.Validate(q.validate)
	}
	if q.hidden {
		field = field.EchoMode(huh.EchoModePassword)
	}
	if err := a.run(field); err != nil {
		return "", err
	}
	switch {
	case q.hidden:
		a.answered(q.title, "(hidden)")
	case value == "":
		a.answered(q.title, q.empty)
	default:
		a.answered(q.title, value)
	}
	return value, nil
}

// choose asks for one of choices with a select field.
func (a *formAsker) choose(title, description string, choices []choice, value string) (string, error) {
	a.explain(description, "")
	options := make([]huh.Option[string], len(choices))
	for i, c := range choices {
		options[i] = huh.NewOption(c.label, c.value)
	}
	field := huh.NewSelect[string]().Title(title).Description(description).Options(options...).Value(&value)
	if len(choices) > 8 {
		field = field.Height(10)
	}
	if err := a.run(field); err != nil {
		return "", err
	}
	a.answered(title, value)
	return value, nil
}

// confirm asks a yes or no question with a confirm field.
func (a *formAsker) confirm(title string, value bool) (bool, error) {
	field := huh.NewConfirm().Title(title).Affirmative("Yes").Negative("No").Value(&value)
	if err := a.run(field); err != nil {
		return false, err
	}
	return value, nil
}

// show writes an answer line.
func (a *formAsker) show(title, value string) {
	ui.Answer(a.shown, title, value)
}

// enrollFlagOrder is the order of the flags in the command that the wizard prints.
var enrollFlagOrder = []string{
	"server", "ca-cert", "tls-ca-cert", flagRef, "secret-file", "mac", "cert", "key", "type",
	flagTemplateCert, flagSubject, flagSAN, flagKeyUsage, flagExtKeyUsage, "key-type", "new-key", "csr",
	"cert-out", "key-out", "chain-out",
}

// enrollWizard asks for the enroll settings that the command line leaves out. Each answer is set
// on its flag, so the usual checks apply and the printed command repeats the request.
type enrollWizard struct {
	cmd *cobra.Command
	o   *enrollOptions
	ask asker
	out io.Writer
	// signed is set when the request is signed with an existing certificate.
	signed bool
	// typedSecret is set when the shared secret was typed into the wizard.
	typedSecret bool
}

// startEnrollWizard runs the wizard for --interactive or for a command line without flags on a
// terminal.
func startEnrollWizard(cmd *cobra.Command, o *enrollOptions) error {
	in, out := cmd.InOrStdin(), cmd.ErrOrStderr()
	switch {
	case !o.interactive && (!noFlags(cmd) || !wizardTerminal(in, out)):
		return nil
	case o.interactive && o.json:
		return errors.New("--interactive cannot be used with --json")
	case o.interactive && !wizardTerminal(in, out):
		return errors.New("--interactive needs a terminal")
	}
	w := &enrollWizard{
		cmd: cmd,
		o:   o,
		ask: newAsker(cmd.Context(), in, out),
		out: colorprofile.NewWriter(out, os.Environ()),
	}
	return w.run()
}

// noFlags reports whether the command line sets no flags other than --color.
func noFlags(cmd *cobra.Command) bool {
	n := 0
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if f.Name != "color" {
			n++
		}
	})
	return n == 0
}

// run asks the questions, prints the equivalent command and asks before the request is sent.
func (w *enrollWizard) run() error {
	_, _ = fmt.Fprintln(w.out, "Answer a few questions to request a certificate. Ctrl-C stops without sending anything.")
	_, _ = fmt.Fprintln(w.out)
	steps := []func() error{w.server, w.trust, w.protection, w.requestType, w.subject, w.altNames, w.keyType, w.outputs}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}

	_, _ = fmt.Fprintf(w.out, "\nThe same request without questions:\n  %s\n",
		commandLine(w.cmd, enrollFlagOrder, "interactive", "color"))
	if w.typedSecret {
		_, _ = fmt.Fprintf(w.out, "That command asks for the shared secret unless %s or --secret-file provides it.\n",
			secret.EnvVar)
	}
	_, _ = fmt.Fprintln(w.out)
	send, err := w.ask.confirm("Send the request?", true)
	switch {
	case err != nil:
		return err
	case !send:
		return errEnrollCancelled
	}
	return nil
}

// given reports whether the command line sets the flag.
func (w *enrollWizard) given(name string) bool {
	return w.cmd.Flags().Changed(name)
}

// set stores an answer in its flag. An answer that matches the default leaves the flag unset, which
// keeps the printed command short.
func (w *enrollWizard) set(name, value string) error {
	f := w.cmd.Flags().Lookup(name)
	if value == f.DefValue && !f.Changed {
		return nil
	}
	return w.cmd.Flags().Set(name, value)
}

// server asks for the server URL.
func (w *enrollWizard) server() error {
	const title = "CMP server"
	if w.given("server") {
		w.ask.show(title, w.o.server)
		return nil
	}
	v, err := w.ask.input(question{
		title:       title,
		description: "The URL where the CA accepts CMP requests.",
		placeholder: "https://ca.example.com/.well-known/cmp",
		validate: func(s string) error {
			if !isServerURL(strings.TrimSpace(s)) {
				return errors.New("enter an http or https URL")
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	return w.set("server", strings.TrimSpace(v))
}

// trust asks for the CA certificate to expect.
func (w *enrollWizard) trust() error {
	const title = "CA certificate"
	if w.given("ca-cert") {
		w.ask.show(title, strings.Join(w.o.caCerts, ", "))
		return nil
	}
	v, err := w.ask.input(question{
		title:       title,
		description: "A file with the certificate of the CA to accept. Leave empty to trust the CA that answers.",
		empty:       "trust the CA that answers",
		validate:    optional(checkCertificates),
	})
	if err != nil || strings.TrimSpace(v) == "" {
		return err
	}
	return w.set("ca-cert", strings.TrimSpace(v))
}

// Answers to the protection question.
const (
	protectSecret = "shared secret"
	protectCert   = "certificate"
)

// protection asks how the request is protected and for the credentials.
func (w *enrollWizard) protection() error {
	mode := protectSecret
	switch {
	case w.given("cert") || w.given("key"):
		mode = protectCert
	case w.given(flagRef) || w.given("secret-file"):
	default:
		var err error
		mode, err = w.ask.choose("Authentication", "How the request proves who sends it.", []choice{
			{"Shared secret from the CA, for a first certificate", protectSecret},
			{"Existing certificate and private key", protectCert},
		}, protectSecret)
		if err != nil {
			return err
		}
	}
	if mode == protectCert {
		w.signed = true
		return w.certificate()
	}
	return w.sharedSecret()
}

// sharedSecret asks for the reference and the shared secret.
func (w *enrollWizard) sharedSecret() error {
	if w.given(flagRef) {
		w.ask.show("Reference", w.o.ref)
	} else {
		v, err := w.ask.input(question{
			title:       "Reference",
			description: "The name the CA gave the shared secret, often a device ID.",
			validate:    required,
		})
		if err != nil {
			return err
		}
		if err := w.set(flagRef, strings.TrimSpace(v)); err != nil {
			return err
		}
	}

	const title = "Shared secret"
	if w.given("secret-file") {
		w.ask.show(title, "from "+w.o.secretFile)
		return nil
	}
	if _, ok := os.LookupEnv(secret.EnvVar); ok {
		w.ask.show(title, "from "+secret.EnvVar)
		return nil
	}
	v, err := w.ask.input(question{
		title:       title,
		description: "It is used for this request only and is not printed.",
		hidden:      true,
		validate: func(s string) error {
			if s == "" {
				return errors.New("enter the shared secret")
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	w.o.protection.secret, w.typedSecret = []byte(v), true
	return nil
}

// certificate asks for the certificate and key that sign the request.
func (w *enrollWizard) certificate() error {
	if w.given("cert") {
		w.ask.show("Certificate", w.o.certFile)
	} else {
		v, err := w.ask.input(question{
			title:       "Certificate",
			description: "The file with the certificate that signs the request. It may also hold the chain.",
			validate:    checkCertificates,
		})
		if err != nil {
			return err
		}
		if err := w.set("cert", strings.TrimSpace(v)); err != nil {
			return err
		}
	}
	if w.given("key") {
		w.ask.show("Private key", w.o.keyFile)
		return nil
	}
	v, err := w.ask.input(question{
		title:       "Private key",
		description: "The file with the private key of that certificate.",
		validate:    checkKey,
	})
	if err != nil {
		return err
	}
	return w.set("key", strings.TrimSpace(v))
}

// requestType asks for the request type, offering the types that fit the protection.
func (w *enrollWizard) requestType() error {
	const title = "Request"
	switch {
	case w.given("type"):
		w.ask.show(title, w.o.reqType)
		return nil
	case w.o.csr != "":
		// --csr needs p10cr, which validate reports if --type does not say so.
		return nil
	}
	choices, value := []choice{
		{"First certificate for this device (ir)", typeIR},
		{"Another certificate (cr)", typeCR},
	}, typeIR
	if w.signed {
		choices, value = []choice{
			{"Renew this certificate with a new key (kur)", typeKUR},
			{"Another certificate (cr)", typeCR},
		}, typeKUR
	}
	v, err := w.ask.choose(title, "", choices, value)
	if err != nil {
		return err
	}
	return w.set("type", v)
}

// asksName reports whether the request takes its names from the wizard. A key update repeats the
// names of the old certificate and a PKCS#10 request carries its own.
func (w *enrollWizard) asksName() bool {
	return w.o.reqType != typeKUR && w.o.csr == ""
}

// subject asks for the subject name.
func (w *enrollWizard) subject() error {
	const title = "Subject"
	switch {
	case !w.asksName():
		return nil
	case w.given(flagSubject):
		w.ask.show(title, w.o.subject)
		return nil
	}
	q := question{
		title:       title,
		description: "The name in the certificate, such as CN=device-42,O=Example.",
		placeholder: "CN=device-42",
		empty:       "none",
		validate: optional(func(s string) error {
			_, err := dn.ParseName(s)
			return err
		}),
	}
	if !w.signed {
		// Without a subject or alternative names the request uses CN=<reference>, so that is the
		// answer to start from.
		if commonName("CN="+w.o.ref) == w.o.ref {
			q.value = "CN=" + w.o.ref
		}
	}
	v, err := w.ask.input(q)
	if err != nil || strings.TrimSpace(v) == "" {
		return err
	}
	return w.set(flagSubject, strings.TrimSpace(v))
}

// altNames asks for the subject alternative names.
func (w *enrollWizard) altNames() error {
	const title = "Alternative names"
	switch {
	case !w.asksName():
		return nil
	case w.given(flagSAN):
		w.ask.show(title, strings.Join(w.o.sans, ", "))
		return nil
	}
	// A signed request has no reference to fall back on for its name.
	needed := w.signed && w.o.subject == ""
	v, err := w.ask.input(question{
		title:       title,
		description: "DNS names, IP addresses, email addresses or URIs, separated by commas.",
		placeholder: "device-42.example.com, 192.0.2.7",
		empty:       "none",
		validate: func(s string) error {
			names := splitList(s)
			if len(names) == 0 {
				if needed {
					return errors.New("enter at least one name, because the subject is empty")
				}
				return nil
			}
			_, err := dn.SubjectAltName(names, false)
			return err
		},
	})
	if err != nil {
		return err
	}
	for _, name := range splitList(v) {
		if err := w.cmd.Flags().Set(flagSAN, name); err != nil {
			return err
		}
	}
	return nil
}

// keyType asks for the type of the new key.
func (w *enrollWizard) keyType() error {
	const title = "Key type"
	switch {
	case w.given("new-key"):
		w.ask.show("Key", w.o.newKey)
		return nil
	case w.o.csr != "":
		return nil
	case w.given("key-type"):
		w.ask.show(title, w.o.keyType)
		return nil
	}
	names := keys.TypeNames()
	choices := make([]choice, len(names))
	for i, name := range names {
		choices[i] = choice{label: name + keyTypeHint(name), value: name}
	}
	v, err := w.ask.choose(title, "The type of the new key pair.", choices, keys.DefaultType)
	if err != nil {
		return err
	}
	return w.set("key-type", v)
}

// keyTypeHint describes a key type in the list of key types.
func keyTypeHint(name string) string {
	switch {
	case name == keys.DefaultType:
		return "  accepted by most CAs"
	case strings.HasPrefix(name, "ml-dsa-"):
		return "  post-quantum"
	case strings.HasPrefix(name, "mldsa"):
		return "  post-quantum composite with a classical key"
	}
	return ""
}

// outputs asks where to save the certificate and the new key.
func (w *enrollWizard) outputs() error {
	if w.given("cert-out") {
		w.ask.show("Save certificate to", w.o.certOut)
	} else {
		v, err := w.ask.input(question{
			title:    "Save certificate to",
			value:    w.fileName() + ".pem",
			validate: w.checkOutput(""),
		})
		if err != nil {
			return err
		}
		if err := w.set("cert-out", strings.TrimSpace(v)); err != nil {
			return err
		}
	}

	const title = "Save private key to"
	switch {
	case w.o.newKey != "" || w.o.csr != "":
		return nil
	case w.given("key-out"):
		w.ask.show(title, w.o.keyOut)
		return nil
	}
	v, err := w.ask.input(question{
		title:       title,
		description: "The new key is saved unencrypted, readable only by you.",
		value:       strings.TrimSuffix(w.o.certOut, filepath.Ext(w.o.certOut)) + ".key",
		validate:    w.checkOutput(w.o.certOut),
	})
	if err != nil {
		return err
	}
	return w.set("key-out", strings.TrimSpace(v))
}

// unsafeFileName matches the runs of characters that a suggested file name leaves out.
var unsafeFileName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// fileName suggests a file name without extension for the new certificate, from the name it is
// requested for.
func (w *enrollWizard) fileName() string {
	name := commonName(w.o.subject)
	if name == "" && !w.signed {
		name = w.o.ref
	}
	if name == "" && w.signed {
		if certs, err := pemfile.ReadCertificates(w.o.certFile); err == nil {
			name = certs[0].Subject.CommonName
		}
	}
	name = strings.Trim(unsafeFileName.ReplaceAllString(name, "-"), ".-")
	if name == "" {
		name = "certificate"
	}
	if w.o.reqType == typeKUR {
		// The old certificate probably has the plain name.
		name += "-new"
	}
	return name
}

// commonName returns the common name in an RFC 4514 name. It returns "" when there is none or the
// name does not parse.
func commonName(s string) string {
	name, err := dn.ParseName(s)
	if err != nil {
		return ""
	}
	// ParseName keeps the attributes in ExtraNames, so the common name is found by reading them back.
	var parsed pkix.Name
	rdns := name.ToRDNSequence()
	parsed.FillFromRDNSequence(&rdns)
	return parsed.CommonName
}

// checkOutput returns a validator for an output file, which must differ from other.
func (w *enrollWizard) checkOutput(other string) func(string) error {
	return func(s string) error {
		path := strings.TrimSpace(s)
		switch {
		case path == "":
			return errors.New("enter a file name")
		case other != "" && filepath.Clean(path) == filepath.Clean(other):
			return errors.New("enter a different file than for the certificate")
		}
		if _, err := os.Stat(path); err == nil && !w.o.force {
			return fmt.Errorf("%s already exists, enter another file", path)
		}
		return pemfile.CheckWritable(path, w.o.force)
	}
}

// required rejects an empty answer.
func required(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("an answer is required")
	}
	return nil
}

// optional accepts an empty answer and checks the others with check.
func optional(check func(string) error) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return nil
		}
		return check(s)
	}
}

// checkCertificates checks that the file in s holds certificates.
func checkCertificates(s string) error {
	_, err := pemfile.ReadCertificates(strings.TrimSpace(s))
	return err
}

// checkKey checks that the file in s holds a private key. An encrypted key passes, because its
// password is asked for when the request is sent.
func checkKey(s string) error {
	path := strings.TrimSpace(s)
	data, err := os.ReadFile(path) //nolint:gosec // G304: the user names the file to read.
	if err != nil {
		return err
	}
	if _, err := keys.Parse(data); err != nil && !errors.Is(err, keys.ErrEncrypted) {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// splitList splits a comma-separated answer and drops empty items.
func splitList(s string) []string {
	var items []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}
