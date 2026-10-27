package cli

import (
	"bufio"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
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
	revokeCert     string
	serial         string
	issuer         string
	reason         string
	invalidityDate string
	yes            bool
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
			"By default certrally revokes the certificate in --cert and signs the request with it, as RFC 9483 " +
			"asks. An authority revoking for someone else names that certificate with --revoke-cert, or with " +
			"--serial and --issuer when it has no copy of it, and signs with its own --cert or shared secret.\n\n" +
			"--invalidity-date tells the CA when the key was compromised or the certificate became invalid, " +
			"for the CRL entry. certificateHold suspends a certificate and removeFromCRL releases it, if the CA " +
			"supports holds. On a terminal certrally asks before it sends the request, unless --yes is given.\n\n" +
			exitStatusHelp,
		Example: "  certrally revoke --server https://ca.example.com/.well-known/cmp \\\n" +
			"    --cert device.pem --key device.key --reason keyCompromise\n" +
			"  certrally revoke --server https://ca.example.com/.well-known/cmp \\\n" +
			"    --ref ra-1 --serial 0x1A2B --issuer 'CN=Example CA' --invalidity-date 2026-10-01",
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
	f.StringVar(&o.serial, "serial", "", "revoke the certificate with this serial number, decimal, 0x hex or "+
		"colon-separated hex, issued by --issuer")
	f.StringVar(&o.issuer, "issuer", "", "issuer of the certificate named with --serial, such as CN=Example CA")
	f.StringVar(&o.reason, "reason", "unspecified", "revocation reason, such as keyCompromise or superseded")
	f.StringVar(&o.invalidityDate, "invalidity-date", "", "time the key was compromised or the certificate "+
		"became invalid, as RFC 3339 or YYYY-MM-DD")
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

// parseSerial reads a --serial value: decimal, hex with a 0x prefix or the colon-separated hex that
// certrally prints.
func parseSerial(s string) (*big.Int, error) {
	digits, base := s, 10
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		digits, base = s[2:], 16
	case strings.Contains(s, ":"):
		digits, base = strings.ReplaceAll(s, ":", ""), 16
	}
	// SetString takes a sign, which a serial number has not, and the colons must separate digits.
	malformed := strings.ContainsAny(s, "+-") || strings.Contains(s, "::") ||
		strings.HasPrefix(s, ":") || strings.HasSuffix(s, ":")
	serial, ok := new(big.Int).SetString(digits, base)
	if !ok || malformed {
		return nil, fmt.Errorf("invalid --serial %q, want a decimal number, hex with 0x or colon-separated hex", s)
	}
	return serial, nil
}

// parseInvalidityDate reads an --invalidity-date value as RFC 3339 or as a date, which means midnight UTC.
func parseInvalidityDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid --invalidity-date %q, "+
		"want RFC 3339 such as 2026-10-01T12:00:00Z or a date such as 2026-10-01", s)
}

// revokeTarget names the certificate to revoke: the certificate itself, or its issuer and serial
// number when the requester has no copy of it.
type revokeTarget struct {
	// cert is nil when the certificate is known by issuer and serial number only.
	cert   *x509.Certificate
	issuer pkix.Name
	serial *big.Int
}

// target reads the certificate to revoke from the flags.
func (o *revokeOptions) target() (*revokeTarget, error) {
	if o.serial != "" || o.issuer != "" {
		if o.serial == "" || o.issuer == "" {
			return nil, errors.New("--serial and --issuer are given together")
		}
		if o.revokeCert != "" {
			return nil, errors.New("--revoke-cert and --serial name the certificate twice, give one of them")
		}
		serial, err := parseSerial(o.serial)
		if err != nil {
			return nil, err
		}
		issuer, err := dn.ParseName(o.issuer)
		if err != nil {
			return nil, fmt.Errorf("--issuer: %w", err)
		}
		return &revokeTarget{issuer: issuer, serial: serial}, nil
	}
	if !o.signed() && o.revokeCert == "" {
		return nil, errors.New("--revoke-cert, or --serial with --issuer, is required with a shared secret")
	}
	path := o.revokeCert
	if path == "" {
		path = o.certFile
	}
	certs, err := pemfile.ReadCertificates(path)
	if err != nil {
		return nil, err
	}
	return &revokeTarget{cert: certs[0], issuer: certs[0].Issuer, serial: certs[0].SerialNumber}, nil
}

// send asks the CA to revoke the target.
func (t *revokeTarget) send(ctx context.Context, c *client.Client, reason pkicmp.CRLReason, creds pkicmp.Credentials, opts []client.RequestOption) error {
	if t.cert != nil {
		return c.SendRR(ctx, t.cert, reason, creds, opts...)
	}
	return c.SendRRBySerial(ctx, t.issuer, t.serial, reason, creds, opts...)
}

// issuerName returns the issuer in RFC 4514 form, as the certificate encodes it when it is known.
func (t *revokeTarget) issuerName() string {
	if t.cert != nil {
		return ui.Sanitize(dn.Format(t.cert.RawIssuer))
	}
	return ui.Sanitize(dn.String(t.issuer.ToRDNSequence()))
}

// question asks whether to revoke the target.
func (t *revokeTarget) question(reason pkicmp.CRLReason) string {
	if t.cert != nil {
		return fmt.Sprintf("Revoke %s, serial %s, for %s?",
			ui.Sanitize(dn.Format(t.cert.RawSubject)), serialText(t.serial), reason)
	}
	return fmt.Sprintf("Revoke serial %s issued by %s, for %s?", serialText(t.serial), t.issuerName(), reason)
}

// fields describes the revoked certificate.
func (t *revokeTarget) fields(reason pkicmp.CRLReason, invalidityDate time.Time) []ui.Field {
	var fields []ui.Field
	if t.cert != nil {
		fields = append(fields, ui.Field{Name: fieldSubject, Value: ui.Sanitize(dn.Format(t.cert.RawSubject))})
	}
	fields = append(fields,
		ui.Field{Name: fieldIssuer, Value: t.issuerName()},
		ui.Field{Name: fieldSerial, Value: serialText(t.serial)},
		ui.Field{Name: fieldReason, Value: reason.String()},
	)
	if !invalidityDate.IsZero() {
		fields = append(fields, ui.Field{Name: fieldInvalidityDate, Value: invalidityDate.UTC().Format(timeLayout)})
	}
	return fields
}

// json returns the JSON result of the revocation.
func (t *revokeTarget) json(reason pkicmp.CRLReason, invalidityDate time.Time) *revokeJSON {
	return &revokeJSON{
		Certificate:    certificateResult(t.cert),
		Issuer:         t.issuerName(),
		Serial:         serialHex(t.serial),
		Reason:         reason.String(),
		InvalidityDate: invalidityDate.UTC(),
	}
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
	var invalidityDate time.Time
	if o.invalidityDate != "" {
		if invalidityDate, err = parseInvalidityDate(o.invalidityDate); err != nil {
			return err
		}
	}
	target, err := o.target()
	if err != nil {
		return err
	}

	if !o.yes {
		ok, err := confirm(stdin, p.stderr, target.question(reason))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("revocation cancelled")
		}
	}

	_, _, err = exchange(ctx, &o.connection, &o.protection, stdin, p,
		func(ctx context.Context, c *client.Client, pr *protected) (struct{}, error) {
			opts := pr.reqOpts
			if !invalidityDate.IsZero() {
				opts = append(slices.Clone(opts), client.WithInvalidityDate(invalidityDate))
			}
			return struct{}{}, target.send(ctx, c, reason, pr.creds, opts)
		})
	if err != nil {
		return err
	}
	p.result(revokeTitle(reason), target.fields(reason, invalidityDate), target.json(reason, invalidityDate))
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
