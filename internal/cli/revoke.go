package cli

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/ui"
)

// revokeOptions holds the revoke command line.
type revokeOptions struct {
	connection
	protection
	outputOptions
	revokeCert string
	reason     string
	yes        bool
}

// reasonNames lists the --reason values, the RFC 5280 reason codes.
var reasonNames = func() []string {
	var names []string
	for r := pkicmp.CRLReasonUnspecified; r <= pkicmp.CRLReasonAACompromise; r++ {
		if r.Valid() {
			names = append(names, r.String())
		}
	}
	return names
}()

// newRevokeCommand returns the revoke command.
func newRevokeCommand() *cobra.Command {
	o := &revokeOptions{}
	cmd := &cobra.Command{
		Use:   "revoke --server URL --cert FILE --key FILE [flags]",
		Short: "Ask the CA to revoke a certificate",
		Long: "Ask the CA to revoke a certificate.\n\n" +
			"RFC 9483 signs the request with the certificate being revoked, so by default certrally revokes the " +
			"certificate in --cert. An authority revoking for someone else names that certificate with " +
			"--revoke-cert and signs with its own --cert or shared secret.\n\n" +
			"certificateHold suspends a certificate and removeFromCRL releases it, if the CA supports holds. " +
			"On a terminal certrally asks before it sends the request, unless --yes is given.\n\n" +
			exitStatusHelp,
		Example: "  certrally revoke --server https://ca.example.com/.well-known/cmp \\\n" +
			"    --cert device.pem --key device.key --reason keyCompromise",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runRevoke(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.connection.addFlags(cmd, 5*time.Minute, "limit for the whole exchange, including polling")
	o.protection.addFlags(cmd)
	o.outputOptions.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.revokeCert, "revoke-cert", "", "revoke the certificate in this file instead of --cert")
	f.StringVar(&o.reason, "reason", "unspecified", "revocation reason, such as keyCompromise or superseded")
	f.BoolVarP(&o.yes, "yes", "y", false, "do not ask for confirmation")
	_ = cmd.RegisterFlagCompletionFunc("reason", fixedCompletion(reasonNames))
	return cmd
}

// parseReason returns the reason code for a --reason value, ignoring case.
func parseReason(s string) (pkicmp.CRLReason, error) {
	for r := pkicmp.CRLReasonUnspecified; r <= pkicmp.CRLReasonAACompromise; r++ {
		if r.Valid() && strings.EqualFold(r.String(), s) {
			return r, nil
		}
	}
	return 0, fmt.Errorf("invalid --reason %q, want one of %s", s, strings.Join(reasonNames, ", "))
}

// runRevoke performs the revoke command.
func runRevoke(ctx context.Context, o *revokeOptions, p *printer, stdin io.Reader) error {
	if err := o.connection.validate(); err != nil {
		return err
	}
	if err := o.protection.validate(); err != nil {
		return err
	}
	reason, err := parseReason(o.reason)
	if err != nil {
		return err
	}
	if !o.signed() && o.revokeCert == "" {
		return errors.New("--revoke-cert is required with a shared secret")
	}
	path := o.revokeCert
	if path == "" {
		path = o.certFile
	}
	certs, err := pemfile.ReadCertificates(path)
	if err != nil {
		return err
	}
	target := certs[0]

	if !o.yes {
		question := fmt.Sprintf("Revoke %s, serial %s, for %s?",
			ui.Sanitize(dn.Format(target.RawSubject)), formatSerial(target), reason)
		ok, err := confirm(stdin, p.stderr, question)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("revocation cancelled")
		}
	}

	_, _, err = exchange(ctx, &o.connection, &o.protection, stdin, p,
		func(ctx context.Context, c *client.Client, pr *protected) (struct{}, error) {
			return struct{}{}, c.SendRR(ctx, target, reason, pr.creds, pr.reqOpts...)
		})
	if err != nil {
		return err
	}
	p.result(revokeTitle(reason), revokeFields(target, reason), &revokeJSON{
		Certificate: certificateResult(target),
		Reason:      reason.String(),
	})
	return nil
}

// revokeTitle names the outcome of an accepted revocation request.
func revokeTitle(reason pkicmp.CRLReason) string {
	switch reason {
	case pkicmp.CRLReasonCertificateHold:
		return "Certificate placed on hold"
	case pkicmp.CRLReasonRemoveFromCRL:
		return "Certificate released from hold"
	default:
		return "Certificate revoked"
	}
}

// revokeFields describes the revoked certificate.
func revokeFields(cert *x509.Certificate, reason pkicmp.CRLReason) []ui.Field {
	return []ui.Field{
		{Name: fieldSubject, Value: ui.Sanitize(dn.Format(cert.RawSubject))},
		{Name: fieldIssuer, Value: ui.Sanitize(dn.Format(cert.RawIssuer))},
		{Name: fieldSerial, Value: formatSerial(cert)},
		{Name: fieldReason, Value: reason.String()},
	}
}

// confirm asks a yes or no question on a terminal. Without a terminal there is nobody to ask, so the
// answer is yes, which keeps scripts working.
func confirm(stdin io.Reader, prompt io.Writer, question string) (bool, error) {
	f, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return true, nil
	}
	_, _ = fmt.Fprintf(prompt, "%s [y/N] ", question)
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
