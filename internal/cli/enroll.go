package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/colorprofile"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
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

// macAlgorithms lists the --mac values.
var macAlgorithms = []string{"pbmac1", "pbm"}

// enrollOptions holds the enroll command line.
type enrollOptions struct {
	server      string
	reqType     string
	ref         string
	mac         string
	secretFile  string
	certFile    string
	keyFile     string
	extraCerts  string
	serverCerts []string
	trusted     []string
	tlsTrusted  string
	subject     string
	sans        []string
	keyType     string
	newKey      string
	csr         string
	certOut     string
	keyOut      string
	chainOut    string
	force       bool
	recipient   string
	sender      string
	certProfile string
	timeout     time.Duration
	quiet       bool
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
			"Exit status: 0 issued, 1 usage or local error, 2 server unreachable or not speaking CMP, " +
			"3 rejected by the CA, 4 protocol or verification failure, " +
			"5 issued but the confirmation failed.",
		Example: "  certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \\\n" +
			"    --secret-file secret.txt --subject CN=device-42 --san device-42.example.com \\\n" +
			"    --trusted ca.pem --cert-out device.pem --key-out device.key\n\n" +
			"  certrally enroll --server https://ca.example.com/.well-known/cmp --type kur \\\n" +
			"    --cert device.pem --key device.key --trusted ca.pem \\\n" +
			"    --cert-out device-new.pem --key-out device-new.key",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnroll(cmd.Context(), o, cmd.OutOrStdout(), cmd.ErrOrStderr(), cmd.InOrStdin())
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.server, "server", "", "address of the CMP server, an http or https URL")
	f.StringVar(&o.reqType, "type", typeIR, "request type: ir, cr, kur or p10cr")
	f.StringVar(&o.ref, "ref", "", "reference that identifies the shared secret to the CA")
	f.StringVar(&o.mac, "mac", "pbmac1", "shared-secret MAC algorithm: pbmac1 or pbm")
	f.StringVar(&o.secretFile, "secret-file", "", "read the shared secret from a file, or - for standard input")
	f.StringVar(&o.certFile, "cert", "", "sign the request with this certificate file, which may include the chain")
	f.StringVar(&o.keyFile, "key", "", "private key for --cert")
	f.StringVar(&o.extraCerts, "extra-certs", "", "send the certificates in this file in extraCerts")
	f.StringArrayVar(&o.serverCerts, "server-cert", nil, "certificate the CA signs responses with, if responses omit it")
	f.StringArrayVar(&o.trusted, "trusted", nil, "trust anchor for responses and the issued certificate (repeatable)")
	f.StringVar(&o.tlsTrusted, "tls-trusted", "", "trust these certificates for HTTPS instead of the system roots")
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
	f.StringVar(&o.recipient, "recipient", "", "name of the CA in the request header")
	f.StringVar(&o.sender, "sender", "", "sender name in the request header")
	f.StringVar(&o.certProfile, "cert-profile", "", "certificate profile to request")
	f.DurationVar(&o.timeout, "timeout", 5*time.Minute, "limit for the whole exchange, including polling")
	f.BoolVarP(&o.quiet, "quiet", "q", false, "print only warnings and errors")

	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("cert-out")
	cmd.MarkFlagsRequiredTogether("cert", "key")
	cmd.MarkFlagsMutuallyExclusive("key-type", "new-key", "csr")
	_ = cmd.RegisterFlagCompletionFunc("type", fixedCompletion(requestTypes))
	_ = cmd.RegisterFlagCompletionFunc("mac", fixedCompletion(macAlgorithms))
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(keys.TypeNames()))
	for _, name := range []string{"server", "ref", "subject", "san", "recipient", "sender", "cert-profile", "timeout"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// fixedCompletion offers a fixed list of flag values to shell completion.
func fixedCompletion(values []string) cobra.CompletionFunc {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// validate checks flag combinations that cobra cannot express.
func (o *enrollOptions) validate() error {
	u, err := url.Parse(o.server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--server %q is not an http or https URL", o.server)
	}
	if !slices.Contains(requestTypes, o.reqType) {
		return fmt.Errorf("invalid --type %q, want one of %s", o.reqType, strings.Join(requestTypes, ", "))
	}
	if !slices.Contains(macAlgorithms, o.mac) {
		return fmt.Errorf("invalid --mac %q, want pbmac1 or pbm", o.mac)
	}
	if err := o.validateProtection(); err != nil {
		return err
	}
	generated := o.csr == "" && o.newKey == ""
	switch {
	case generated && o.keyOut == "":
		return errors.New("--key-out is required to save the generated key")
	case !generated && o.keyOut != "":
		return errors.New("--key-out is only used with a generated key")
	case o.timeout <= 0:
		return errors.New("--timeout must be positive")
	}
	outputs := []string{o.certOut, o.keyOut, o.chainOut}
	for i, a := range outputs {
		for _, b := range outputs[i+1:] {
			if a != "" && b != "" && filepath.Clean(a) == filepath.Clean(b) {
				return fmt.Errorf("%s is given for two outputs", a)
			}
		}
	}
	return nil
}

// validateProtection checks that exactly one protection is chosen and fits the request type.
func (o *enrollOptions) validateProtection() error {
	signed := o.certFile != ""
	switch {
	case signed && (o.ref != "" || o.secretFile != ""):
		return errors.New("choose one protection: --ref with a shared secret, or --cert and --key")
	case !signed && o.ref == "":
		return errors.New("choose a protection: --ref with a shared secret, or --cert and --key")
	case o.reqType == typeKUR && !signed:
		return errors.New("a kur request updates the certificate in --cert, so --cert and --key are required")
	case signed && len(o.trusted) == 0:
		return errors.New("--trusted is required with --cert, because the CA signs its responses")
	case o.csr != "" && o.reqType != typeP10CR:
		return errors.New("--csr needs --type p10cr")
	case o.csr != "" && (o.subject != "" || len(o.sans) > 0):
		return errors.New("--subject and --san cannot change a request given with --csr")
	}
	return nil
}

// enrollment is a request ready to send.
type enrollment struct {
	creds      pkicmp.Credentials
	signerCert *x509.Certificate
	newKey     crypto.Signer
	csrDER     []byte
	reqOpts    []client.RequestOption
	clientOpts []client.Option
	anchored   bool
}

// runEnroll performs the enroll command.
func runEnroll(ctx context.Context, o *enrollOptions, stdout, stderr io.Writer, stdin io.Reader) error {
	if err := o.validate(); err != nil {
		return err
	}
	for _, out := range []string{o.certOut, o.keyOut, o.chainOut} {
		if out == "" {
			continue
		}
		if err := pemfile.CheckWritable(out, o.force); err != nil {
			return err
		}
	}

	errOut := colorprofile.NewWriter(stderr, os.Environ())
	e, err := o.prepare(stdin, errOut)
	if err != nil {
		return err
	}
	if !e.anchored {
		ui.Warning(errOut, "No --trusted CA: the CA certificate in the response is trusted on first use "+
			"and error messages cannot be verified.")
	}

	recorder := &trace.Recorder{Next: http.DefaultTransport}
	if o.tlsTrusted != "" {
		roots, err := certPool([]string{o.tlsTrusted})
		if err != nil {
			return err
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		recorder.Next = t
	}
	if !o.quiet {
		u, _ := url.Parse(o.server)
		recorder.OnEvent = ui.NewLadder(errOut, "certrally", u.Host).Event
	}
	c := client.NewClient(o.server, append(e.clientOpts, client.WithHTTPClient(&http.Client{Transport: recorder}))...)

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	result, err := o.send(ctx, c, e)
	if !o.quiet && len(recorder.Events()) > 0 {
		_, _ = fmt.Fprintln(errOut)
	}
	if err != nil {
		return o.reportFailure(errOut, err, recorder, e)
	}

	cert := result.Certificate
	chain := issuerChain(cert, append(result.CAPubs, result.ExtraCertificates...))
	saved, err := o.save(cert, e.newKey, chain)
	if err != nil {
		return fmt.Errorf("the certificate was issued but could not be saved: %w", err)
	}
	if o.chainOut != "" && len(chain) == 0 {
		ui.Warning(errOut, "The response carried no issuing CA certificates, so --chain-out was not written.")
	}
	if !o.quiet {
		fields := certificateFields(cert, lastStatus(recorder), saved)
		ui.Report(colorprofile.NewWriter(stdout, os.Environ()), true, "Certificate issued", fields)
	}
	return nil
}

// prepare loads files and builds the credentials, key and options of the request.
func (o *enrollOptions) prepare(stdin io.Reader, prompt io.Writer) (*enrollment, error) {
	e := &enrollment{}
	if o.certFile != "" {
		chain, err := pemfile.ReadCertificates(o.certFile)
		if err != nil {
			return nil, err
		}
		keyData, err := os.ReadFile(o.keyFile)
		if err != nil {
			return nil, err
		}
		key, err := keys.Parse(keyData)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.keyFile, err)
		}
		creds, err := pkicmp.NewSignatureCredentials(key, chain[0], chain[1:]...)
		if err != nil {
			return nil, fmt.Errorf("--cert and --key: %w", err)
		}
		e.creds, e.signerCert = creds, chain[0]
	} else {
		s, err := secret.Source{File: o.secretFile, LookupEnv: os.LookupEnv, Stdin: stdin, Prompt: prompt}.Read()
		if err != nil {
			return nil, err
		}
		var macOpts []pkicmp.MACCredentialOption
		if o.mac == "pbm" {
			macOpts = append(macOpts, pkicmp.WithPBM())
		}
		creds, err := pkicmp.NewMACCredentials(s, macOpts...)
		if err != nil {
			return nil, err
		}
		e.creds = creds
		// RFC 9483 §4.1.5 identifies the shared secret by the sender common name and the senderKID.
		e.reqOpts = append(e.reqOpts, client.WithSenderKID([]byte(o.ref)))
		if o.sender == "" {
			e.reqOpts = append(e.reqOpts, client.WithSender(pkix.Name{CommonName: o.ref}))
		}
	}

	if err := o.prepareKey(e); err != nil {
		return nil, err
	}
	if err := o.prepareTemplate(e); err != nil {
		return nil, err
	}
	return e, o.prepareOptions(e)
}

// prepareKey loads or generates the key to certify, or loads the CSR that carries it.
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
		hasSubject = len(e.signerCert.Subject.Names) > 0
	case len(o.sans) == 0 && o.ref != "":
		// RFC 9483 §4.1.5 lets a device that does not know its name use the reference instead.
		subject, hasSubject = pkix.Name{CommonName: o.ref}, true
	case len(o.sans) == 0:
		return errors.New("--subject or --san is required")
	}

	var extensions []pkix.Extension
	if len(o.sans) > 0 {
		// RFC 5280 §4.2.1.6 requires the extension to be critical when the subject is empty.
		ext, err := dn.SubjectAltName(o.sans, !hasSubject)
		if err != nil {
			return fmt.Errorf("--san: %w", err)
		}
		extensions = append(extensions, ext)
	}

	if o.reqType == typeP10CR {
		tmpl := &x509.CertificateRequest{Subject: subject, ExtraExtensions: extensions}
		der, err := compositex509.CreateCertificateRequest(rand.Reader, tmpl, e.newKey)
		if err != nil {
			return fmt.Errorf("create certificate request: %w", err)
		}
		e.csrDER = der
		return nil
	}
	if o.subject != "" || (o.reqType != typeKUR && hasSubject) {
		e.reqOpts = append(e.reqOpts, client.WithTemplateSubject(subject))
	}
	for _, ext := range extensions {
		e.reqOpts = append(e.reqOpts, client.WithTemplateExtension(ext))
	}
	return nil
}

// prepareOptions sets header fields, trust anchors and extra certificates.
func (o *enrollOptions) prepareOptions(e *enrollment) error {
	if o.sender != "" {
		name, err := dn.ParseName(o.sender)
		if err != nil {
			return fmt.Errorf("--sender: %w", err)
		}
		e.reqOpts = append(e.reqOpts, client.WithSender(name))
	}
	if o.recipient != "" {
		name, err := dn.ParseName(o.recipient)
		if err != nil {
			return fmt.Errorf("--recipient: %w", err)
		}
		e.clientOpts = append(e.clientOpts, client.WithRecipient(name))
	}
	if o.certProfile != "" {
		e.reqOpts = append(e.reqOpts, client.WithCertProfile(o.certProfile))
	}
	if len(o.trusted) > 0 {
		pool, err := certPool(o.trusted)
		if err != nil {
			return err
		}
		e.clientOpts = append(e.clientOpts, client.WithTrustedCAs(pool))
		e.anchored = true
	}
	if len(o.serverCerts) > 0 {
		var certs []*x509.Certificate
		for _, path := range o.serverCerts {
			c, err := pemfile.ReadCertificates(path)
			if err != nil {
				return err
			}
			certs = append(certs, c...)
		}
		e.clientOpts = append(e.clientOpts, client.WithServerCerts(certs))
	}
	if o.extraCerts != "" {
		certs, err := pemfile.ReadCertificates(o.extraCerts)
		if err != nil {
			return err
		}
		e.clientOpts = append(e.clientOpts, client.WithExtraCerts(certs))
	}
	return nil
}

// certPool loads the certificates in paths into a pool.
func certPool(paths []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, path := range paths {
		certs, err := pemfile.ReadCertificates(path)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			pool.AddCert(c)
		}
	}
	return pool, nil
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

// save writes the key, then the certificate and the chain, and returns the paths written. The key
// comes first so that a certificate file never exists without its key.
func (o *enrollOptions) save(cert *x509.Certificate, key crypto.Signer, chain []*x509.Certificate) ([]string, error) {
	var saved []string
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
	keyDesc := ""
	if pub, err := keys.CertificateKey(cert); err == nil {
		keyDesc = keys.Describe(pub)
	}
	return []ui.Field{
		{Name: "Subject", Value: ui.Sanitize(cert.Subject.String())},
		{Name: "Alt names", Value: ui.Sanitize(altNames(cert))},
		{Name: "Issuer", Value: ui.Sanitize(cert.Issuer.String())},
		{Name: "Serial", Value: formatSerial(cert)},
		{Name: "Valid", Value: cert.NotBefore.UTC().Format(timeLayout) + " to " + cert.NotAfter.UTC().Format(timeLayout)},
		{Name: "Key", Value: keyDesc},
		{Name: "Status", Value: status},
		{Name: "Saved", Value: strings.Join(saved, ", ")},
	}
}

// timeLayout formats certificate validity times.
const timeLayout = "2006-01-02 15:04 UTC"

// altNames lists the subject alternative names of cert.
func altNames(cert *x509.Certificate) string {
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs))
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	return strings.Join(names, ", ")
}

// formatSerial returns the serial number as colon-separated hex bytes.
func formatSerial(cert *x509.Certificate) string {
	if cert.SerialNumber == nil {
		return ""
	}
	b := cert.SerialNumber.Bytes()
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
