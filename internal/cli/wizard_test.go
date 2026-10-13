package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/colorprofile"
)

// Special answers of a scriptedAsker.
const (
	// keep accepts the answer the question starts with.
	keep = "<keep>"
	// stop stops the wizard as Ctrl-C does.
	stop = "<stop>"
)

// scriptedAsker answers the wizard's questions by title and records what it was asked and shown.
type scriptedAsker struct {
	t       *testing.T
	answers map[string]string
	asked   []string
	shown   map[string]string
}

// useWizard makes the wizard run as if on a terminal, with answers from the returned asker.
func useWizard(t *testing.T, answers map[string]string) *scriptedAsker {
	t.Helper()
	a := &scriptedAsker{t: t, answers: answers, shown: map[string]string{}}
	terminal, ask := wizardTerminal, newAsker
	wizardTerminal = func(io.Reader, io.Writer) bool { return true }
	newAsker = func(context.Context, io.Reader, io.Writer) asker { return a }
	t.Cleanup(func() { wizardTerminal, newAsker = terminal, ask })
	return a
}

// answer returns the scripted answer to the question with title.
func (a *scriptedAsker) answer(title string) (string, error) {
	a.t.Helper()
	a.asked = append(a.asked, title)
	v, ok := a.answers[title]
	switch {
	case !ok:
		a.t.Fatalf("unexpected question %q", title)
	case v == stop:
		return "", errEnrollCancelled
	}
	return v, nil
}

// input answers q and checks the answer as the form would.
func (a *scriptedAsker) input(q question) (string, error) {
	v, err := a.answer(q.title)
	if err != nil {
		return "", err
	}
	if v == keep {
		v = q.value
	}
	if q.validate != nil {
		if err := q.validate(v); err != nil {
			a.t.Fatalf("the answer %q to %q is invalid: %v", v, q.title, err)
		}
	}
	return v, nil
}

// choose answers with the value of one of choices.
func (a *scriptedAsker) choose(title, _ string, choices []choice, value string) (string, error) {
	v, err := a.answer(title)
	if err != nil {
		return "", err
	}
	if v == keep {
		v = value
	}
	if !slices.ContainsFunc(choices, func(c choice) bool { return c.value == v }) {
		a.t.Fatalf("%q is not a choice of %q", v, title)
	}
	return v, nil
}

// confirm answers yes when the script says "yes".
func (a *scriptedAsker) confirm(title string, _ bool) (bool, error) {
	v, err := a.answer(title)
	return v == "yes", err
}

// show records an answer that came from the command line.
func (a *scriptedAsker) show(title, value string) {
	a.shown[title] = value
}

// printedCommand returns the command that the wizard printed.
func printedCommand(t *testing.T, stderr string) string {
	t.Helper()
	_, after, ok := strings.Cut(stderr, "The same request without questions:\n  ")
	if !ok {
		t.Fatalf("the wizard printed no command:\n%s", stderr)
	}
	line, _, _ := strings.Cut(after, "\n")
	return line
}

// TestEnrollWizard checks a first enrollment through the wizard and that the printed command repeats it.
func TestEnrollWizard(t *testing.T) {
	useSecret(t, "")
	ca := startCA(t, nil)
	t.Chdir(t.TempDir())
	a := useWizard(t, map[string]string{
		"CMP server":          ca.url,
		"CA certificate":      ca.caFile,
		"Authentication":      protectSecret,
		"Reference":           testRef,
		"Shared secret":       testSecret,
		"Request":             keep,
		"Subject":             keep,
		"Alternative names":   testRef + ".example.com, ip:192.0.2.7",
		"Key type":            "ml-dsa-65",
		"Save certificate to": keep,
		"Save private key to": keep,
		"Send the request?":   "yes",
	})
	code, _, errOut := run(t, "enroll")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if len(a.asked) != len(a.answers) {
		t.Errorf("asked %q, want every scripted question", a.asked)
	}
	cert := readCert(t, testRef+".pem")
	if cert.Subject.CommonName != testRef || len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 1 {
		t.Errorf("issued %s with %v and %v", cert.Subject, cert.DNSNames, cert.IPAddresses)
	}
	if _, err := os.Stat(testRef + ".key"); err != nil {
		t.Error(err)
	}

	command := printedCommand(t, errOut)
	want := "certrally enroll --server " + ca.url + " --ca-cert " + ca.caFile + " --ref " + testRef +
		" --subject CN=" + testRef + " --san " + testRef + ".example.com --san ip:192.0.2.7 --key-type ml-dsa-65" +
		" --cert-out " + testRef + ".pem --key-out " + testRef + ".key"
	if command != want {
		t.Errorf("printed command\n%s\nwant\n%s", command, want)
	}
	if strings.Contains(errOut, testSecret) {
		t.Error("the wizard printed the shared secret")
	}
	if !strings.Contains(errOut, "That command asks for the shared secret") {
		t.Errorf("the wizard does not say where the command gets the secret:\n%s", errOut)
	}

	// The printed command makes the same request without questions.
	t.Chdir(t.TempDir())
	useSecret(t, testSecret)
	asked := len(a.asked)
	if code, _, errOut := run(t, strings.Fields(command)[1:]...); code != exitOK {
		t.Fatalf("the printed command exited with %d:\n%s", code, errOut)
	}
	if len(a.asked) != asked {
		t.Errorf("the printed command asked %q", a.asked[asked:])
	}
	if got := readCert(t, testRef+".pem"); got.Subject.CommonName != testRef {
		t.Errorf("the printed command issued %s", got.Subject)
	}
}

// TestEnrollWizardPrefill checks that flags answer their questions and appear in the printed command.
func TestEnrollWizardPrefill(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	certOut := filepath.Join(t.TempDir(), "device.pem")
	a := useWizard(t, map[string]string{
		"CA certificate":      "",
		"Request":             typeCR,
		"Subject":             "CN=device-42,O=Example",
		"Alternative names":   "",
		"Key type":            keep,
		"Save private key to": keep,
		"Send the request?":   "yes",
	})
	code, _, errOut := run(t, "enroll", "--interactive", "--server", ca.url, "--ref", testRef, "--cert-out", certOut)
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	for _, title := range []string{"CMP server", "Authentication", "Reference", "Shared secret", "Save certificate to"} {
		if slices.Contains(a.asked, title) {
			t.Errorf("asked %q, which the command line answers", title)
		}
	}
	wantShown := map[string]string{
		"CMP server": ca.url, "Reference": testRef, "Shared secret": "from CERTRALLY_SECRET", "Save certificate to": certOut,
	}
	for title, want := range wantShown {
		if a.shown[title] != want {
			t.Errorf("shown %q = %q, want %q", title, a.shown[title], want)
		}
	}
	keyOut := strings.TrimSuffix(certOut, ".pem") + ".key"
	want := "certrally enroll --server " + ca.url + " --ref " + testRef + " --type cr --subject CN=device-42,O=Example" +
		" --cert-out " + certOut + " --key-out " + keyOut
	if command := printedCommand(t, errOut); command != want {
		t.Errorf("printed command\n%s\nwant\n%s", command, want)
	}
	if strings.Contains(errOut, "That command asks for the shared secret") {
		t.Error("the wizard explains a secret that it did not ask for")
	}
	if got := readCert(t, certOut); got.Subject.CommonName != "device-42" {
		t.Errorf("issued %s", got.Subject)
	}
}

// TestEnrollWizardKeyUpdate checks that a signed request offers a key update and skips the names.
func TestEnrollWizardKeyUpdate(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	oldCert, oldKey := enrollIR(t, ca)
	t.Chdir(t.TempDir())
	useSecret(t, "")
	a := useWizard(t, map[string]string{
		"CMP server":          ca.url,
		"CA certificate":      ca.caFile,
		"Authentication":      protectCert,
		"Certificate":         oldCert,
		"Private key":         oldKey,
		"Request":             keep,
		"Key type":            keep,
		"Save certificate to": keep,
		"Save private key to": keep,
		"Send the request?":   "yes",
	})
	code, _, errOut := run(t, "enroll")
	if code != exitOK {
		t.Fatalf("enroll exited with %d:\n%s", code, errOut)
	}
	if len(a.asked) != len(a.answers) {
		t.Errorf("asked %q, want every scripted question", a.asked)
	}
	want := "certrally enroll --server " + ca.url + " --ca-cert " + ca.caFile + " --cert " + oldCert + " --key " + oldKey +
		" --type kur --cert-out " + testRef + "-new.pem --key-out " + testRef + "-new.key"
	if command := printedCommand(t, errOut); command != want {
		t.Errorf("printed command\n%s\nwant\n%s", command, want)
	}
	if got := readCert(t, testRef+"-new.pem"); got.Subject.CommonName != testRef {
		t.Errorf("the key update issued %s", got.Subject)
	}
}

// TestEnrollWizardCancel checks that declining or stopping the wizard sends nothing.
func TestEnrollWizardCancel(t *testing.T) {
	useSecret(t, testSecret)
	ca := startCA(t, nil)
	dir := t.TempDir()
	certOut := filepath.Join(dir, "c.pem")
	flags := []string{
		"enroll", "--interactive", "--server", ca.url, "--ca-cert", ca.caFile, "--ref", testRef,
		"--subject", "CN=x", "--san", "x.example.com", "--key-type", "ecdsa-p256",
		"--cert-out", certOut, "--key-out", filepath.Join(dir, "k.pem"),
	}
	for _, answers := range []map[string]string{
		{"Request": keep, "Send the request?": "no"},
		{"Request": stop},
	} {
		a := useWizard(t, answers)
		code, _, errOut := run(t, flags...)
		if code != exitLocal || !strings.Contains(errOut, "nothing was sent") {
			t.Errorf("%v: enroll exited with %d:\n%s", answers, code, errOut)
		}
		if len(a.asked) != len(answers) {
			t.Errorf("%v: asked %q", answers, a.asked)
		}
	}
	if n := ca.requests.Load(); n != 0 {
		t.Errorf("the CA received %d requests", n)
	}
	if _, err := os.Stat(certOut); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a cancelled enrollment wrote %s: %v", certOut, err)
	}
}

// TestEnrollWizardStart checks when the wizard starts and when it refuses to.
func TestEnrollWizardStart(t *testing.T) {
	useSecret(t, testSecret)
	tests := []struct {
		name     string
		terminal bool
		args     []string
		want     string
		asked    bool
	}{
		{"no terminal", false, []string{"enroll"}, `required flag(s) "cert-out", "server" not set`, false},
		{"interactive without terminal", false, []string{"enroll", "--interactive"}, "--interactive needs a terminal", false},
		{"interactive with JSON", true, []string{"enroll", "--interactive", "--json"}, "--interactive cannot be used with --json", false},
		{"flags on a terminal", true, []string{"enroll", "--server", "http://ca.test/cmp"}, `required flag(s) "cert-out" not set`, false},
		{"no flags on a terminal", true, []string{"enroll"}, "nothing was sent", true},
		{"colour on a terminal", true, []string{"enroll", "--color", "never"}, "nothing was sent", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := useWizard(t, map[string]string{"CMP server": stop})
			if !tt.terminal {
				wizardTerminal = func(io.Reader, io.Writer) bool { return false }
			}
			code, _, errOut := run(t, tt.args...)
			if code != exitLocal || !strings.Contains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d with %q:\n%s", code, exitLocal, tt.want, errOut)
			}
			if asked := len(a.asked) > 0; asked != tt.asked {
				t.Errorf("asked %q", a.asked)
			}
		})
	}
}

// TestWizardOutputs checks the suggested file names and the checks of output files.
func TestWizardOutputs(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "taken.pem")
	writeFile(t, existing, []byte("x"))
	tests := []struct {
		o    enrollOptions
		want string
	}{
		{enrollOptions{ref: "device-42"}, "device-42"},
		{enrollOptions{subject: "CN=Lab device/7,O=Example", ref: "r"}, "Lab-device-7"},
		{enrollOptions{subject: "O=Example", ref: "../r"}, "r"},
		{enrollOptions{ref: "*"}, "certificate"},
		{enrollOptions{reqType: typeKUR, ref: "device-42"}, "device-42-new"},
	}
	for _, tt := range tests {
		w := &enrollWizard{o: &tt.o}
		if got := w.fileName(); got != tt.want {
			t.Errorf("fileName for %q and %q = %q, want %q", tt.o.subject, tt.o.ref, got, tt.want)
		}
	}

	w := &enrollWizard{o: &enrollOptions{}}
	check := w.checkOutput(filepath.Join(dir, "cert.pem"))
	for _, tt := range []struct{ path, want string }{
		{"", "enter a file name"},
		{filepath.Join(dir, "cert.pem"), "different file"},
		{existing, "already exists, enter another file"},
		{filepath.Join(dir, "missing", "k.pem"), "no such file"},
		{filepath.Join(dir, "k.pem"), ""},
	} {
		err := check(tt.path)
		if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("checkOutput(%q) = %v, want %q", tt.path, err, tt.want)
		}
	}
	w.o.force = true
	if err := w.checkOutput("")(existing); err != nil {
		t.Errorf("with --force, checkOutput(%q) = %v", existing, err)
	}
}

// TestFormAsker checks the huh forms in accessible mode, which reads answers line by line.
func TestFormAsker(t *testing.T) {
	isolateColorEnv(t)
	ask := func(input string) (*formAsker, *bytes.Buffer) {
		var out bytes.Buffer
		shown := colorprofile.NewWriter(&out, os.Environ())
		return &formAsker{ctx: context.Background(), in: strings.NewReader(input), out: shown, shown: shown, accessible: true}, &out
	}

	a, out := ask("\ndevice-42\n")
	v, err := a.input(question{title: "Reference", description: "The name of the secret.", validate: required})
	if err != nil || v != "device-42" {
		t.Errorf("input = %q, %v, want device-42", v, err)
	}
	for _, want := range []string{"The name of the secret.", "an answer is required"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the form does not show %q:\n%s", want, out)
		}
	}

	a, out = ask("\n")
	v, err = a.input(question{title: "Subject", value: "CN=device-42"})
	if err != nil || v != "CN=device-42" || !strings.Contains(out.String(), "Press Enter for CN=device-42.") {
		t.Errorf("input with a starting answer = %q, %v:\n%s", v, err, out)
	}

	a, _ = ask("2\n")
	v, err = a.choose("Request", "", []choice{{"First", typeIR}, {"Another", typeCR}}, typeIR)
	if err != nil || v != typeCR {
		t.Errorf("choose = %q, %v, want %s", v, err, typeCR)
	}

	a, _ = ask("\n")
	v, err = a.choose("Request", "", []choice{{"First", typeIR}, {"Another", typeCR}}, typeCR)
	if err != nil || v != typeCR {
		t.Errorf("choose with the default = %q, %v, want %s", v, err, typeCR)
	}

	a, _ = ask("n\n")
	if ok, err := a.confirm("Send the request?", true); err != nil || ok {
		t.Errorf("confirm = %v, %v, want false", ok, err)
	}

	a, out = ask("")
	a.show("CMP server", "http://ca.test/cmp")
	if got := out.String(); got != fmt.Sprintf("✓ %s  %s\n", "CMP server", "http://ca.test/cmp") {
		t.Errorf("show wrote %q", got)
	}
}
