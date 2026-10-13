package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// Request types of the enroll command.
const (
	typeIR    = "ir"
	typeCR    = "cr"
	typeKUR   = "kur"
	typeP10CR = "p10cr"
)

// requestTypes lists the --type values.
var requestTypes = []string{typeIR, typeCR, typeKUR, typeP10CR}

// enrollOptions holds the enroll command line.
type enrollOptions struct {
	connection
	protection
	outputOptions
	reqType     string
	subject     string
	sans        []string
	keyType     string
	newKey      string
	csr         string
	certOut     string
	keyOut      string
	chainOut    string
	force       bool
	certProfile string
}

// newEnrollCommand returns the enroll command.
func newEnrollCommand() *cobra.Command {
	o := &enrollOptions{}
	cmd := &cobra.Command{
		Use:   "enroll --server URL --cert-out FILE [flags]",
		Short: "Request a certificate from a CMP server",
		Long: "Request a certificate from a CMP server and save it.\n\n" +
			"With a shared secret (--ref) the request is MAC-protected, which is how a new device gets its first " +
			"certificate. With --cert and --key it is signed with an existing certificate, which cr and kur " +
			"requests normally use. A new key is generated unless --new-key or --csr supplies one.\n\n" +
			"The shared secret is read from --secret-file, the CERTRALLY_SECRET environment variable or a " +
			"prompt, never from the command line.\n\n" +
			exitStatusHelp,
		Example: "  certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \\\n" +
			"    --secret-file secret.txt --subject CN=device-42 --san device-42.example.com \\\n" +
			"    --cert-out device.pem --key-out device.key\n\n" +
			"  certrally enroll --server https://ca.example.com/.well-known/cmp --type kur \\\n" +
			"    --cert device.pem --key device.key --cert-out device-new.pem --key-out device-new.key",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.connection.addFlags(cmd, 5*time.Minute, "limit for the whole exchange, including polling")
	o.protection.addFlags(cmd)
	o.outputOptions.addFlags(cmd)

	f := cmd.Flags()
	f.StringVar(&o.reqType, "type", typeIR, "request type: ir, cr, kur or p10cr")
	f.StringVar(&o.subject, "subject", "", "subject name, such as CN=device-42,O=Example")
	f.StringArrayVar(&o.sans, "san", nil, "subject alternative name: dns:, ip:, email: or uri: value (repeatable)")
	f.StringVar(&o.keyType, "key-type", keys.DefaultType,
		"type of the generated key, such as ecdsa-p384, rsa-3072, ml-dsa-65 or mldsa65-ecdsa-p256-sha512")
	f.StringVar(&o.newKey, "new-key", "", "certify the private key in this file instead of generating one")
	f.StringVar(&o.csr, "csr", "", "send the PKCS#10 request in this file (p10cr)")
	f.StringVar(&o.certOut, "cert-out", "", "write the issued certificate to this file")
	f.StringVar(&o.keyOut, "key-out", "", "write the generated private key to this file")
	f.StringVar(&o.chainOut, "chain-out", "", "write the issuing CA certificates from the response to this file")
	f.BoolVar(&o.force, "force", false, "replace existing output files")
	f.StringVar(&o.certProfile, "cert-profile", "", "certificate profile to request")

	_ = cmd.MarkFlagRequired("cert-out")
	cmd.MarkFlagsMutuallyExclusive("key-type", "new-key", "csr")
	_ = cmd.RegisterFlagCompletionFunc("type", fixedCompletion(requestTypes))
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(keys.TypeNames()))
	for _, name := range []string{"subject", "san", "cert-profile"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// exitStatusHelp documents the exit statuses of the commands that talk to a server.
const exitStatusHelp = "Exit status: 0 success, 1 usage or local error, 2 server unreachable or not speaking CMP, " +
	"3 rejected by the CA, 4 protocol or verification failure, 5 issued but the confirmation failed."

// fixedCompletion offers a fixed list of flag values to shell completion.
func fixedCompletion(values []string) cobra.CompletionFunc {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// validate checks flag combinations that cobra cannot express.
func (o *enrollOptions) validate() error {
	if err := o.connection.validate(); err != nil {
		return err
	}
	if !slices.Contains(requestTypes, o.reqType) {
		return fmt.Errorf("invalid --type %q, want one of %s", o.reqType, strings.Join(requestTypes, ", "))
	}
	if err := o.protection.validate(); err != nil {
		return err
	}
	switch {
	case o.reqType == typeKUR && !o.signed():
		return errors.New("a kur request updates the certificate in --cert, so --cert and --key are required")
	case o.csr != "" && o.reqType != typeP10CR:
		return errors.New("--csr needs --type p10cr")
	case o.csr != "" && (o.subject != "" || len(o.sans) > 0):
		return errors.New("--subject and --san cannot change a request given with --csr")
	}
	generated := o.csr == "" && o.newKey == ""
	switch {
	case generated && o.keyOut == "":
		return errors.New("--key-out is required to save the generated key")
	case !generated && o.keyOut != "":
		return errors.New("--key-out is only used with a generated key")
	}
	if err := o.checkCapture(o.certOut, o.keyOut, o.chainOut); err != nil {
		return err
	}
	return checkOutputs(o.force, o.certOut, o.keyOut, o.chainOut)
}

// checkOutputs rejects a path given for two outputs and outputs that cannot be written, before any
// request is sent. Empty paths and "-" are skipped.
func checkOutputs(force bool, paths ...string) error {
	var seen []string
	for _, p := range paths {
		if p == "" || p == "-" {
			continue
		}
		if slices.Contains(seen, filepath.Clean(p)) {
			return fmt.Errorf("%s is given for two outputs", p)
		}
		seen = append(seen, filepath.Clean(p))
		if err := pemfile.CheckWritable(p, force); err != nil {
			return err
		}
	}
	return nil
}

// enrollment is a request ready to send.
type enrollment struct {
	*protected
	newKey crypto.Signer
	csrDER []byte
}

// runEnroll performs the enroll command.
func runEnroll(ctx context.Context, o *enrollOptions, p *printer, stdin io.Reader) error {
	if err := o.validate(); err != nil {
		return err
	}
	pr, err := o.load(stdin, p.stderr)
	if err != nil {
		return err
	}
	e := &enrollment{protected: pr}
	if err := o.prepareKey(e); err != nil {
		return err
	}
	if err := o.prepareTemplate(e); err != nil {
		return err
	}
	if o.certProfile != "" {
		e.reqOpts = append(e.reqOpts, client.WithCertProfile(o.certProfile))
	}

	s, err := o.open(p, e.chain)
	if err != nil {
		return err
	}
	c, err := s.client(e.clientOpts...)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	s.startLadder()
	result, err := o.send(ctx, c, e)
	s.endLadder()
	if err != nil {
		if confErr, ok := errors.AsType[*client.ConfirmationError](err); ok {
			return o.reportUnconfirmed(s, confErr, e.newKey)
		}
		return s.fail(err)
	}

	cert := result.Certificate
	chain := issuerChain(cert, append(result.CAPubs, result.ExtraCertificates...))
	saved, err := o.save(cert, e.newKey, chain)
	if err != nil {
		return fmt.Errorf("the certificate was issued but could not be saved: %w", err)
	}
	if o.chainOut != "" && len(chain) == 0 {
		p.warn("The response carried no issuing CA certificates, so --chain-out was not written.")
	}
	status := lastStatus(s.recorder)
	p.result("Certificate issued", certificateFields(cert, status, saved), &enrollJSON{
		Status:      status,
		Confirmed:   true,
		Certificate: certificateResult(cert),
		Chain:       certificatesResult(chain),
		Saved:       saved,
	})
	return nil
}

// reportUnconfirmed saves a certificate whose confirmation failed and explains the situation. The
// certificate is kept because retrying could issue a second one.
func (o *enrollOptions) reportUnconfirmed(s *session, confErr *client.ConfirmationError, key crypto.Signer) error {
	saved, saveErr := o.save(confErr.Certificate, key, nil)
	f := &failure{
		code:    exitUnconfirmed,
		Title:   "The certificate was issued but the confirmation failed",
		Message: confErr.Err.Error(),
		Note: "The CA may keep or revoke this certificate. " +
			"Check with the CA before retrying, because a retry can issue a second certificate.",
	}
	fields := []ui.Field{
		errorField(f.Message),
		{Name: fieldSaved, Value: strings.Join(saved, ", ")},
		{Name: fieldNote, Value: f.Note},
	}
	if saveErr != nil {
		fields = append(fields, ui.Field{Name: "Save error", Value: saveErr.Error()})
		s.p.doc.Warnings = append(s.p.doc.Warnings, "The certificate could not be saved: "+saveErr.Error())
	}
	s.p.doc.Result = &enrollJSON{
		Status:      lastStatus(s.recorder),
		Certificate: certificateResult(confErr.Certificate),
		Chain:       []*certificateJSON{},
		Saved:       saved,
	}
	return s.p.fail(f, confErr, fields...)
}

// prepareKey loads or generates the key to certify. With --csr it loads the request that carries the key.
func (o *enrollOptions) prepareKey(e *enrollment) error {
	switch {
	case o.csr != "":
		der, err := pemfile.ReadCSR(o.csr)
		if err != nil {
			return err
		}
		e.csrDER = der
	case o.newKey != "":
		data, err := os.ReadFile(o.newKey)
		if err != nil {
			return err
		}
		key, err := keys.Parse(data)
		if err != nil {
			return fmt.Errorf("%s: %w", o.newKey, err)
		}
		e.newKey = key
	default:
		key, err := keys.Generate(o.keyType)
		if err != nil {
			return err
		}
		e.newKey = key
	}
	return nil
}

// prepareTemplate sets the requested subject and subject alternative names.
func (o *enrollOptions) prepareTemplate(e *enrollment) error {
	if o.csr != "" {
		return nil
	}
	var subject pkix.Name
	hasSubject := o.subject != ""
	switch {
	case hasSubject:
		name, err := dn.ParseName(o.subject)
		if err != nil {
			return fmt.Errorf("--subject: %w", err)
		}
		subject = name
	case o.reqType == typeKUR:
		// The key update repeats the subject of the old certificate.
		hasSubject = len(e.chain[0].Subject.Names) > 0
	case len(o.sans) == 0 && o.ref != "":
		// RFC 9483 §4.1.5 lets a device that does not know its name use the reference instead.
		subject, hasSubject = pkix.Name{CommonName: o.ref}, true
	case len(o.sans) == 0:
		return errors.New("--subject or --san is required")
	}

	extensions, err := sanExtensions(o.sans, hasSubject)
	if err != nil {
		return err
	}
	if o.reqType == typeP10CR {
		e.csrDER, err = createCSR(subject, extensions, e.newKey)
		return err
	}
	if o.subject != "" || (o.reqType != typeKUR && hasSubject) {
		e.reqOpts = append(e.reqOpts, client.WithTemplateSubject(subject))
	}
	for _, ext := range extensions {
		e.reqOpts = append(e.reqOpts, client.WithTemplateExtension(ext))
	}
	return nil
}

// sanExtensions builds the subjectAltName extension for --san values, if any. RFC 5280 §4.2.1.6
// requires it to be critical when the subject is empty.
func sanExtensions(sans []string, hasSubject bool) ([]pkix.Extension, error) {
	if len(sans) == 0 {
		return nil, nil
	}
	ext, err := dn.SubjectAltName(sans, !hasSubject)
	if err != nil {
		return nil, fmt.Errorf("--san: %w", err)
	}
	return []pkix.Extension{ext}, nil
}

// createCSR returns a PKCS#10 request for key, signed with it.
func createCSR(subject pkix.Name, extensions []pkix.Extension, key crypto.Signer) ([]byte, error) {
	tmpl := &x509.CertificateRequest{Subject: subject, ExtraExtensions: extensions}
	der, err := compositex509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	return der, nil
}

// send performs the exchange for the requested type.
func (o *enrollOptions) send(ctx context.Context, c *client.Client, e *enrollment) (*client.EnrollResult, error) {
	switch o.reqType {
	case typeCR:
		return c.SendCR(ctx, e.newKey, e.creds, e.reqOpts...)
	case typeKUR:
		return c.SendKUR(ctx, e.newKey, e.creds, e.reqOpts...)
	case typeP10CR:
		return c.SendP10CR(ctx, e.csrDER, e.creds, e.reqOpts...)
	default:
		return c.SendIR(ctx, e.newKey, e.creds, e.reqOpts...)
	}
}

// save writes the key, then the certificate and the chain. It returns the paths written. The key
// comes first so that a certificate file never exists without its key.
func (o *enrollOptions) save(cert *x509.Certificate, key crypto.Signer, chain []*x509.Certificate) ([]string, error) {
	saved := []string{}
	if o.keyOut != "" && key != nil {
		data, err := keys.MarshalPEM(key)
		if err != nil {
			return saved, err
		}
		if err := pemfile.Write(o.keyOut, data, 0o600, o.force); err != nil {
			return saved, err
		}
		saved = append(saved, o.keyOut)
	}
	if err := pemfile.Write(o.certOut, pemfile.EncodeCertificates([]*x509.Certificate{cert}), 0o644, o.force); err != nil {
		return saved, err
	}
	saved = append(saved, o.certOut)
	if o.chainOut != "" && len(chain) > 0 {
		if err := pemfile.Write(o.chainOut, pemfile.EncodeCertificates(chain), 0o644, o.force); err != nil {
			return saved, err
		}
		saved = append(saved, o.chainOut)
	}
	return saved, nil
}

// issuerChain returns the certificates from candidates that link cert towards a root, issuer first.
// It stops at a self-issued certificate or when no issuer is found.
func issuerChain(cert *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	var chain []*x509.Certificate
	used := func(c *x509.Certificate) bool {
		return c.Equal(cert) || slices.ContainsFunc(chain, c.Equal)
	}
	for cur := cert; !bytes.Equal(cur.RawIssuer, cur.RawSubject); {
		var next *x509.Certificate
		for _, c := range candidates {
			if c == nil || used(c) || !bytes.Equal(c.RawSubject, cur.RawIssuer) {
				continue
			}
			// Prefer the key identifiers when both are present, since a CA renewal keeps the name.
			if len(cur.AuthorityKeyId) > 0 && len(c.SubjectKeyId) > 0 && !bytes.Equal(cur.AuthorityKeyId, c.SubjectKeyId) {
				continue
			}
			next = c
			break
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		cur = next
	}
	return chain
}

// lastStatus returns the status of the last certificate response, such as "accepted".
func lastStatus(r *trace.Recorder) string {
	for _, ev := range slices.Backward(r.Events()) {
		if ev.Kind == trace.Response && ev.Message != nil && ev.Message.Status != "" {
			return ev.Message.Status
		}
	}
	return ""
}

// certificateFields describes an issued certificate for the result report.
func certificateFields(cert *x509.Certificate, status string, saved []string) []ui.Field {
	return append(describeCertificate(cert),
		ui.Field{Name: "Status", Value: status},
		ui.Field{Name: fieldSaved, Value: strings.Join(saved, ", ")},
	)
}

// describeCertificate returns the fields that identify a certificate.
func describeCertificate(cert *x509.Certificate) []ui.Field {
	keyDesc := ""
	if pub, err := keys.CertificateKey(cert); err == nil {
		keyDesc = keys.Describe(pub)
	}
	return []ui.Field{
		{Name: fieldSubject, Value: ui.Sanitize(cert.Subject.String())},
		{Name: "Alt names", Value: ui.Sanitize(strings.Join(altNames(cert), ", "))},
		{Name: fieldIssuer, Value: ui.Sanitize(cert.Issuer.String())},
		{Name: "Serial", Value: formatSerial(cert)},
		{Name: "Valid", Value: cert.NotBefore.UTC().Format(timeLayout) + " to " + cert.NotAfter.UTC().Format(timeLayout)},
		{Name: fieldKey, Value: keyDesc},
	}
}

// timeLayout formats certificate validity times.
const timeLayout = "2006-01-02 15:04 UTC"

// altNames lists the subject alternative names of cert.
func altNames(cert *x509.Certificate) []string {
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs))
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	return names
}

// formatSerial returns the serial number as colon-separated hex bytes.
func formatSerial(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	return hexBytes(cert.SerialNumber.Bytes())
}

// hexBytes returns b as colon-separated upper-case hex.
func hexBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
