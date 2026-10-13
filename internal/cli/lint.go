package cli

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/profile"
	"github.com/misiektoja/certrally/internal/ui"
)

// lintOptions holds the lint command line.
type lintOptions struct {
	outputOptions
	caCerts []string
}

// newLintCommand returns the lint command.
func newLintCommand() *cobra.Command {
	o := &lintOptions{}
	cmd := &cobra.Command{
		Use:   "lint FILE... [flags]",
		Short: "Check recorded CMP responses against RFC 9483",
		Long: "Check CMP responses against the rules that the compatible profile reports as warnings, and check " +
			"that each response carries the transactionID and recipNonce of its request.\n\n" +
			fileArgsHelp + "\n\n" +
			"Each response is checked as the answer to the request before it in the same capture run. The " +
			"messages of the other files form one exchange in command line order. Without --ca-cert the " +
			"certificates of the first response of each exchange are trusted, as during the run.\n\n" +
			"Exit status: 0 no deviations, 1 a file cannot be read or holds no response to check, " +
			"6 a response breaks a rule.",
		Example: "  certrally lint enroll.jsonl\n" +
			"  certrally lint ir.der ip.der certConf.der pkiconf.der",
		Args: cobra.MinimumNArgs(1),
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, args []string, p *printer) error {
			return runLint(o, p, args, cmd.InOrStdin())
		}),
	}
	cmd.Flags().StringArrayVar(&o.caCerts, "ca-cert", nil,
		"trust the CA certificates in this file instead of those in the first response (repeatable)")
	o.outputOptions.addFlags(cmd)
	return cmd
}

// exchangeKey identifies the exchange a message belongs to: a run of a capture file, or the zero
// key for all other files.
type exchangeKey struct {
	file string
	run  int
}

// lintExchange is the state of one exchange while lint walks its messages.
type lintExchange struct {
	requests []*pkicmp.PKIMessage
	// trusted are the certificates the client trusted. Without --ca-cert they come from the first response.
	trusted      []*x509.Certificate
	trustDecided bool
}

// runLint performs the lint command.
func runLint(o *lintOptions, p *printer, paths []string, stdin io.Reader) error {
	caCerts, err := readCACerts(o.caCerts)
	if err != nil {
		return err
	}
	msgs, err := readMessages(paths, stdin)
	if err != nil {
		return err
	}
	result := &lintJSON{Findings: []lintFindingJSON{}}
	exchanges := map[exchangeKey]*lintExchange{}
	w := p.reportWriter()
	for _, m := range msgs {
		key := exchangeKey{}
		if m.Run > 0 {
			key = exchangeKey{file: m.File, run: m.Run}
		}
		ex := exchanges[key]
		if ex == nil {
			ex = &lintExchange{}
			exchanges[key] = ex
		}
		if m.Request {
			ex.requests = append(ex.requests, m.Msg)
			continue
		}
		body := m.Msg.Body.Type.String()
		if len(ex.requests) == 0 {
			result.Skipped++
			p.warn(fmt.Sprintf("%s: the %s response has no request before it, so it was not checked.", m.Source, body))
			continue
		}
		if !ex.trustDecided {
			ex.trusted, ex.trustDecided = caCerts, true
			if len(caCerts) == 0 {
				ex.trusted = responseCerts(m.Msg)
			}
		}
		req := ex.requests[len(ex.requests)-1]
		findings := profile.CheckReply(ex.requests, m.Msg)
		findings = append(findings, profile.Check(req, m.Msg, ex.trusted)...)
		result.Checked++
		for _, f := range findings {
			result.Findings = append(result.Findings, lintFindingJSON{Source: m.Source, Body: body, Text: f.Text, Rule: f.Rule})
			if p.text() {
				ui.Warning(w, ui.Sanitize(m.Source)+": "+f.String())
			}
		}
	}

	p.doc.Result = result
	responses := count(result.Checked, "response", "responses")
	switch {
	case result.Checked == 0:
		return p.fail(&failure{
			code:    exitLocal,
			Title:   "No response was checked",
			Message: "The files hold no response with a request before it.",
		}, errors.New("no response to check"))
	case len(result.Findings) > 0:
		title := count(len(result.Findings), "deviation", "deviations") + " in " + responses
		// The findings printed above are the details of the failure.
		return p.fail(&failure{
			code:    exitProfile,
			Title:   title,
			Message: "Responses break rules of RFC 9483 or RFC 9810.",
		}, errors.New(title), []ui.Field{}...)
	}
	p.result("No deviations in "+responses, nil, result)
	return nil
}

// responseCerts returns the certificates in the extraCerts and caPubs of msg, which a session
// without --ca-cert trusts on first use.
func responseCerts(msg *pkicmp.PKIMessage) []*x509.Certificate {
	all := msg.ExtraCerts
	if rep := certRep(msg.Body); rep != nil {
		all = slices.Concat(all, rep.CAPubs)
	}
	var certs []*x509.Certificate
	for i := range all {
		if cert, err := all[i].Parse(); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}
