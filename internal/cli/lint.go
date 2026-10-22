package cli

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

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
		Short: "Check recorded CMP and EST responses against RFC 9483 and RFC 7030",
		Long: "Check CMP responses against the rules that the compatible profile reports as warnings, and check " +
			"that each response carries the transactionID and recipNonce of its request.\n\n" +
			fileArgsHelp + "\n\n" +
			"Each response is checked as the answer to the request before it in the same capture run. The " +
			"messages of the other files form one exchange in command line order. Without --ca-cert the " +
			"certificates of the first response of each exchange are trusted, as during the run.\n\n" +
			"EST responses are checked against the RFC 7030 rules of the compatible profile. Those rules " +
			"concern the HTTP response, so only EST responses in a capture file are checked.\n\n" +
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
	report := func(source, body string, findings []profile.Finding) {
		result.Checked++
		for _, f := range findings {
			result.Findings = append(result.Findings, lintFindingJSON{Source: source, Body: body, Text: f.Text, Rule: f.Rule})
			if p.text() {
				ui.Warning(w, ui.Sanitize(source)+": "+f.String())
			}
		}
	}
	rfcs := map[string]bool{}
	for _, m := range msgs {
		if m.EST != nil {
			switch {
			case m.Request:
			case m.Run == 0:
				result.Skipped++
				p.warn(fmt.Sprintf("%s: the EST rules concern the HTTP response, which only a capture file "+
					"records, so it was not checked.", m.Source))
			default:
				findings := profile.CheckEST(estResponse(*m.EST))
				rfcs[protocolEST] = rfcs[protocolEST] || len(findings) > 0
				report(m.Source, m.EST.Operation, findings)
			}
			continue
		}
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
		rfcs[protocolCMP] = rfcs[protocolCMP] || len(findings) > 0
		report(m.Source, body, findings)
	}

	p.doc.Result = result
	responses := count(result.Checked, "response", "responses")
	switch {
	case result.Checked == 0:
		return p.fail(&failure{
			code:    exitLocal,
			Title:   "No response was checked",
			Message: "The files hold no CMP response with a request before it and no EST response in a capture file.",
		}, errors.New("no response to check"))
	case len(result.Findings) > 0:
		title := count(len(result.Findings), "deviation", "deviations") + " in " + responses
		// The findings printed above are the details of the failure.
		var broken []string
		if rfcs[protocolCMP] {
			broken = append(broken, "RFC 9483", "RFC 9810")
		}
		if rfcs[protocolEST] {
			broken = append(broken, "RFC 7030")
		}
		return p.fail(&failure{
			code:    exitProfile,
			Title:   title,
			Message: "Responses break rules of " + orList(broken) + ".",
		}, errors.New(title), []ui.Field{}...)
	}
	p.result("No deviations in "+responses, nil, result)
	return nil
}

// orList joins items as "a", "a or b" or "a, b or c".
func orList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
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
