package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// genmOptions holds the flags shared by the general message commands.
type genmOptions struct {
	connection
	protection
	out   string
	force bool
}

// addFlags registers the flags of a general message command. outHelp is empty for commands that
// write no file.
func (o *genmOptions) addFlags(cmd *cobra.Command, outHelp string) {
	o.connection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange")
	o.protection.addFlags(cmd)
	if outHelp != "" {
		cmd.Flags().StringVar(&o.out, "out", "", outHelp+", or - for standard output")
		cmd.Flags().BoolVar(&o.force, "force", false, "replace an existing output file")
	}
}

// validate checks the shared flags.
func (o *genmOptions) validate() error {
	if err := o.connection.validate(); err != nil {
		return err
	}
	if err := o.protection.validate(); err != nil {
		return err
	}
	return checkOutputs(o.force, o.out)
}

// genmLong completes the description of a general message command.
const genmLong = "\n\nThe request is protected like enroll requests, with --ref and a shared secret or with --cert " +
	"and --key.\n\n" + exitStatusHelp

// newCACertsCommand returns the cacerts command, which also serves as cmp genm cacerts.
func newCACertsCommand(use string) *cobra.Command {
	o := &genmOptions{}
	cmd := &cobra.Command{
		Use:   use + " --server URL [flags]",
		Short: "Get the CA certificates from the server",
		Long:  "Ask the server for its intermediate and issuing CA certificates (RFC 9483 §4.3.1)." + genmLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCACerts(cmd.Context(), o, cmd.OutOrStdout(), cmd.ErrOrStderr(), cmd.InOrStdin())
		},
	}
	o.addFlags(cmd, "write the certificates to this file")
	return cmd
}

// runCACerts performs the cacerts command.
func runCACerts(ctx context.Context, o *genmOptions, stdout, stderr io.Writer, stdin io.Reader) error {
	if err := o.validate(); err != nil {
		return err
	}
	certs, _, err := exchange(ctx, &o.connection, &o.protection, stdin, stderr,
		func(ctx context.Context, c *client.Client, pr *protected) ([]*x509.Certificate, error) {
			return c.GetCACertificates(ctx, pr.creds, pr.reqOpts...)
		})
	if err != nil {
		return err
	}
	if o.out != "" && len(certs) > 0 {
		if err := writeData(o.out, pemfile.EncodeCertificates(certs), 0o644, o.force, stdout); err != nil {
			return err
		}
	}
	if o.quiet {
		return nil
	}
	w := reportWriter(stdout, stderr, o.out)
	if len(certs) == 0 {
		ui.Report(w, true, "The CA has no CA certificates to send", nil)
		return nil
	}
	title := "Received " + count(len(certs), "CA certificate", "CA certificates")
	ui.Report(w, true, title, []ui.Field{{Name: fieldSaved, Value: strings.Join(savedPaths(o.out), ", ")}})
	for _, cert := range certs {
		ui.Section(w, ui.Sanitize(cert.Subject.String()), caCertFields(cert))
	}
	return nil
}

// caCertFields describes a CA certificate in a list.
func caCertFields(cert *x509.Certificate) []ui.Field {
	keyDesc := ""
	if pub, err := keys.CertificateKey(cert); err == nil {
		keyDesc = keys.Describe(pub)
	}
	issuer := ui.Sanitize(cert.Issuer.String())
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		issuer = "self-signed"
	}
	sum := sha256.Sum256(cert.Raw)
	return []ui.Field{
		{Name: fieldIssuer, Value: issuer},
		{Name: "Valid", Value: cert.NotBefore.UTC().Format(timeLayout) + " to " + cert.NotAfter.UTC().Format(timeLayout)},
		{Name: fieldKey, Value: keyDesc},
		{Name: "SHA-256", Value: hexBytes(sum[:])},
	}
}

// newCMPCommand returns the cmp command group for CMP-specific operations.
func newCMPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cmp",
		Short: "CMP-specific operations",
		Args:  cobra.NoArgs,
	}
	genm := &cobra.Command{
		Use:   "genm",
		Short: "Send a general message (RFC 9483 §4.3)",
		Long: "Send a general message that asks the server for information rather than a certificate. " +
			"Each subcommand sends one of the RFC 9483 §4.3 support messages, and raw sends any info type.",
		Args: cobra.NoArgs,
	}
	genm.AddCommand(
		newCACertsCommand("cacerts"),
		newRootUpdateCommand(),
		newTemplateCommand(),
		newCRLCommand(),
		newCRLUpdateCommand(),
		newRawGenMCommand(),
	)
	cmd.AddCommand(genm)
	return cmd
}

// newRootUpdateCommand returns cmp genm rootupdate.
func newRootUpdateCommand() *cobra.Command {
	o := &genmOptions{}
	var oldRoot string
	cmd := &cobra.Command{
		Use:   "rootupdate --server URL --old-root FILE [flags]",
		Short: "Ask whether the root CA certificate has been replaced",
		Long: "Ask for the replacement of a root CA certificate (RFC 9483 §4.3.2). The new root is accepted only " +
			"when the old root has certified it." + genmLong,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if oldRoot == "" {
				return errors.New("--old-root is required")
			}
			if err := o.validate(); err != nil {
				return err
			}
			certs, err := pemfile.ReadCertificates(oldRoot)
			if err != nil {
				return err
			}
			update, _, err := exchange(cmd.Context(), &o.connection, &o.protection, cmd.InOrStdin(), cmd.ErrOrStderr(),
				func(ctx context.Context, c *client.Client, pr *protected) (*pkicmp.RootCAKeyUpdate, error) {
					return c.GetRootCAUpdate(ctx, certs[0], pr.creds, pr.reqOpts...)
				})
			if err != nil {
				return err
			}
			return reportRootUpdate(o, update, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	o.addFlags(cmd, "write the new root CA certificate to this file")
	cmd.Flags().StringVar(&oldRoot, "old-root", "", "the root CA certificate the update replaces")
	return cmd
}

// reportRootUpdate saves and describes a root CA update.
func reportRootUpdate(o *genmOptions, update *pkicmp.RootCAKeyUpdate, stdout, stderr io.Writer) error {
	w := reportWriter(stdout, stderr, o.out)
	if update == nil {
		if !o.quiet {
			ui.Report(w, true, "No root CA update is available", nil)
		}
		return nil
	}
	if o.out != "" {
		data := pemfile.EncodeCertificates([]*x509.Certificate{update.NewWithNew})
		if err := writeData(o.out, data, 0o644, o.force, stdout); err != nil {
			return err
		}
	}
	if o.quiet {
		return nil
	}
	fields := append(describeCertificate(update.NewWithNew),
		ui.Field{Name: "Old root", Value: "certifies the new root"},
		ui.Field{Name: fieldSaved, Value: strings.Join(savedPaths(o.out), ", ")},
	)
	ui.Report(w, true, "A new root CA certificate is available", fields)
	return nil
}

// newTemplateCommand returns cmp genm template.
func newTemplateCommand() *cobra.Command {
	o := &genmOptions{}
	var profile string
	cmd := &cobra.Command{
		Use:   "template --server URL [flags]",
		Short: "Get the certificate request template",
		Long: "Ask which subject, extensions and key types the CA expects in a certificate request " +
			"(RFC 9483 §4.3.3)." + genmLong,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			tmpl, _, err := exchange(cmd.Context(), &o.connection, &o.protection, cmd.InOrStdin(), cmd.ErrOrStderr(),
				func(ctx context.Context, c *client.Client, pr *protected) (*pkicmp.CertReqTemplate, error) {
					opts := pr.reqOpts
					if profile != "" {
						opts = append(opts, client.WithCertProfile(profile))
					}
					return c.GetCertReqTemplate(ctx, pr.creds, opts...)
				})
			if err != nil || o.quiet {
				return err
			}
			w := reportWriter(cmd.OutOrStdout(), cmd.ErrOrStderr())
			if tmpl == nil {
				ui.Report(w, true, "The CA imposes no requirements", nil)
				return nil
			}
			ui.Report(w, true, "Certificate request template", templateFields(tmpl))
			return nil
		},
	}
	o.addFlags(cmd, "")
	cmd.Flags().StringVar(&profile, "cert-profile", "", "certificate profile to get the template for")
	return cmd
}

// templateFields describes a certificate request template.
func templateFields(tmpl *pkicmp.CertReqTemplate) []ui.Field {
	// pkix.Name drops attributes with empty values, which are the ones the requester fills in, so the
	// subject is formatted from the RDN sequence.
	rdns := tmpl.Template.Subject.DirectoryName
	subject, note := ui.Sanitize(rdns.String()), ""
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if s, ok := atv.Value.(string); ok && s == "" {
				note = "Attributes without a value are for you to fill in."
			}
		}
	}
	var exts []string
	var parsed []pkix.Extension
	if len(tmpl.Template.Extensions) > 0 {
		if _, err := asn1.Unmarshal(tmpl.Template.Extensions, &parsed); err != nil {
			exts = append(exts, "unreadable")
		}
	}
	for _, e := range parsed {
		name := extensionName(e.Id)
		if e.Critical {
			name += " (critical)"
		}
		exts = append(exts, name)
	}
	keyTypes := make([]string, 0, len(tmpl.KeySpec))
	for _, spec := range tmpl.KeySpec {
		keyTypes = append(keyTypes, keySpecName(spec))
	}
	return []ui.Field{
		{Name: fieldSubject, Value: subject},
		{Name: "Extensions", Value: strings.Join(exts, ", ")},
		{Name: "Key types", Value: strings.Join(keyTypes, ", ")},
		{Name: fieldNote, Value: note},
	}
}

// extensionNames maps common certificate extensions to display names.
var extensionNames = map[string]string{
	"2.5.29.14":         "subjectKeyIdentifier",
	"2.5.29.15":         "keyUsage",
	"2.5.29.17":         "subjectAltName",
	"2.5.29.19":         "basicConstraints",
	"2.5.29.31":         "cRLDistributionPoints",
	"2.5.29.32":         "certificatePolicies",
	"2.5.29.35":         "authorityKeyIdentifier",
	"2.5.29.37":         "extKeyUsage",
	"1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
}

// extensionName returns a display name for an extension, or its dotted OID.
func extensionName(oid asn1.ObjectIdentifier) string {
	if name, ok := extensionNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// Key specification controls of RFC 9483 §4.3.3.
var (
	oidRegCtrlAlgID     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 11}
	oidRegCtrlRSAKeyLen = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 12}
)

// Public key algorithms that a key specification names.
var (
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// curveNames maps named curve OIDs to display names.
var curveNames = map[string]string{
	"1.2.840.10045.3.1.7": "P-256",
	"1.3.132.0.34":        "P-384",
	"1.3.132.0.35":        "P-521",
}

// keySpecName describes one key type of a template key specification.
func keySpecName(spec pkicmp.AttributeTypeAndValue) string {
	switch {
	case spec.Type.Equal(oidRegCtrlRSAKeyLen):
		var bits int
		if _, err := asn1.Unmarshal(spec.Value, &bits); err == nil {
			return fmt.Sprintf("RSA %d", bits)
		}
	case spec.Type.Equal(oidRegCtrlAlgID):
		var alg pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(spec.Value, &alg); err == nil {
			return publicKeyAlgorithmName(alg)
		}
	}
	return spec.Type.String()
}

// publicKeyAlgorithmName returns a display name for a public key algorithm identifier.
func publicKeyAlgorithmName(alg pkix.AlgorithmIdentifier) string {
	switch {
	case alg.Algorithm.Equal(oidECPublicKey):
		var curve asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &curve); err == nil {
			if name, ok := curveNames[curve.String()]; ok {
				return "ECDSA " + name
			}
		}
		return "ECDSA"
	case alg.Algorithm.Equal(oidRSAEncryption):
		return "RSA"
	}
	if alg, ok := compositemldsa.AlgorithmFromOID(alg.Algorithm); ok {
		return alg.String()
	}
	return trace.AlgorithmName(alg.Algorithm)
}

// newCRLCommand returns cmp genm crl.
func newCRLCommand() *cobra.Command {
	o := &genmOptions{}
	cmd := &cobra.Command{
		Use:   "crl --server URL [flags]",
		Short: "Get the current CRL",
		Long:  "Ask for the current certificate revocation list (RFC 9810 §5.3.19.6)." + genmLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			crl, s, err := exchange(cmd.Context(), &o.connection, &o.protection, cmd.InOrStdin(), cmd.ErrOrStderr(),
				func(ctx context.Context, c *client.Client, pr *protected) (*x509.RevocationList, error) {
					return c.GetCurrentCRL(ctx, pr.creds, pr.reqOpts...)
				})
			if err != nil {
				return err
			}
			return reportCRL(o, s, crl, "The CA has no CRL", cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	o.addFlags(cmd, "write the CRL to this file")
	return cmd
}

// newCRLUpdateCommand returns cmp genm crlupdate.
func newCRLUpdateCommand() *cobra.Command {
	o := &genmOptions{}
	var crlFile, issuerFile string
	cmd := &cobra.Command{
		Use:   "crlupdate --server URL (--crl FILE | --crl-issuer FILE) [flags]",
		Short: "Get a CRL newer than the one you have",
		Long: "Ask for a CRL newer than the one in --crl, or for any CRL from the CA in --crl-issuer " +
			"(RFC 9483 §4.3.4)." + genmLong,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			status, err := crlStatus(crlFile, issuerFile)
			if err != nil {
				return err
			}
			crl, s, err := exchange(cmd.Context(), &o.connection, &o.protection, cmd.InOrStdin(), cmd.ErrOrStderr(),
				func(ctx context.Context, c *client.Client, pr *protected) (*x509.RevocationList, error) {
					return c.GetCRLUpdate(ctx, status, pr.creds, pr.reqOpts...)
				})
			if err != nil {
				return err
			}
			return reportCRL(o, s, crl, "No newer CRL is available", cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	o.addFlags(cmd, "write the CRL to this file")
	cmd.Flags().StringVar(&crlFile, "crl", "", "the newest CRL you have")
	cmd.Flags().StringVar(&issuerFile, "crl-issuer", "", "certificate of the CA that issues the CRL, when you have none")
	cmd.MarkFlagsMutuallyExclusive("crl", "crl-issuer")
	cmd.MarkFlagsOneRequired("crl", "crl-issuer")
	return cmd
}

// crlStatus describes the CRL the client holds, from a CRL file or the certificate of its issuer.
func crlStatus(crlFile, issuerFile string) (pkicmp.CRLStatus, error) {
	if issuerFile != "" {
		certs, err := pemfile.ReadCertificates(issuerFile)
		if err != nil {
			return pkicmp.CRLStatus{}, err
		}
		return pkicmp.CRLStatus{Source: pkicmp.NewCRLIssuerSource(certs[0].RawSubject)}, nil
	}
	crl, err := pemfile.ReadCRL(crlFile)
	if err != nil {
		return pkicmp.CRLStatus{}, err
	}
	return pkicmp.CRLStatus{Source: pkicmp.NewCRLIssuerSource(crl.RawIssuer), ThisUpdate: crl.ThisUpdate}, nil
}

// reportCRL saves and describes a CRL. Its signature is checked against the trusted CA certificates,
// because the CMP protection covers only the transfer.
func reportCRL(o *genmOptions, s *session, crl *x509.RevocationList, none string, stdout, stderr io.Writer) error {
	w := reportWriter(stdout, stderr, o.out)
	if crl == nil {
		if !o.quiet {
			ui.Report(w, true, none, nil)
		}
		return nil
	}
	if o.out != "" {
		data := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw})
		if err := writeData(o.out, data, 0o644, o.force, stdout); err != nil {
			return err
		}
	}
	signature := "not checked, the issuer certificate is unknown"
	for _, cert := range s.anchors {
		if !bytes.Equal(cert.RawSubject, crl.RawIssuer) {
			continue
		}
		if err := compositex509.CheckRevocationListSignatureFrom(crl, cert); err != nil {
			signature = "invalid: " + err.Error()
			ui.Warning(s.errOut, "The CRL signature does not verify against "+ui.Sanitize(cert.Subject.String())+".")
			continue
		}
		signature = "valid"
		break
	}
	if o.quiet {
		return nil
	}
	number := ""
	if crl.Number != nil {
		number = crl.Number.String()
	}
	ui.Report(w, true, "Received a CRL", []ui.Field{
		{Name: fieldIssuer, Value: ui.Sanitize(crl.Issuer.String())},
		{Name: "This update", Value: crl.ThisUpdate.UTC().Format(timeLayout)},
		{Name: "Next update", Value: formatOptionalTime(crl.NextUpdate)},
		{Name: "Number", Value: number},
		{Name: "Revoked", Value: strconv.Itoa(len(crl.RevokedCertificateEntries))},
		{Name: "Signature", Value: signature},
		{Name: fieldSaved, Value: strings.Join(savedPaths(o.out), ", ")},
	})
	return nil
}

// formatOptionalTime formats t, or returns "" for the zero time.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

// infoTypeNames maps the names accepted by cmp genm raw to the info types of RFC 9810 Appendix A.
var infoTypeNames = map[string]asn1.ObjectIdentifier{
	"currentCRL":        pkicmp.InfoTypeCurrentCRL,
	"caCerts":           pkicmp.InfoTypeCACerts,
	"rootCaKeyUpdate":   pkicmp.InfoTypeRootCAKeyUpdate,
	"certReqTemplate":   pkicmp.InfoTypeCertReqTemplate,
	"rootCaCert":        pkicmp.InfoTypeRootCACert,
	"crlStatusList":     pkicmp.InfoTypeCRLStatusList,
	"crls":              pkicmp.InfoTypeCRLs,
	"unsupportedOIDs":   pkicmp.InfoTypeUnsupportedOIDs,
	"implicitConfirm":   {1, 3, 6, 1, 5, 5, 7, 4, 13},
	"confirmWaitTime":   {1, 3, 6, 1, 5, 5, 7, 4, 14},
	"certProfile":       {1, 3, 6, 1, 5, 5, 7, 4, 21},
	"origPKIMessage":    {1, 3, 6, 1, 5, 5, 7, 4, 15},
	"suppLangTags":      {1, 3, 6, 1, 5, 5, 7, 4, 16},
	"preferredSymmAlg":  {1, 3, 6, 1, 5, 5, 7, 4, 4},
	"caProtEncCert":     {1, 3, 6, 1, 5, 5, 7, 4, 1},
	"signKeyPairTypes":  {1, 3, 6, 1, 5, 5, 7, 4, 2},
	"encKeyPairTypes":   {1, 3, 6, 1, 5, 5, 7, 4, 3},
	"caKeyUpdateInfo":   {1, 3, 6, 1, 5, 5, 7, 4, 5},
	"keyPairParamReq":   {1, 3, 6, 1, 5, 5, 7, 4, 10},
	"keyPairParamRep":   {1, 3, 6, 1, 5, 5, 7, 4, 11},
	"revPassphrase":     {1, 3, 6, 1, 5, 5, 7, 4, 12},
	"kemCiphertextInfo": {1, 3, 6, 1, 5, 5, 7, 4, 24},
}

// infoTypeName returns the name of an info type, or its dotted OID.
func infoTypeName(oid asn1.ObjectIdentifier) string {
	for name, o := range infoTypeNames {
		if o.Equal(oid) {
			return name
		}
	}
	return oid.String()
}

// parseInfoType accepts an info type name or a dotted OID.
func parseInfoType(s string) (asn1.ObjectIdentifier, error) {
	for name, oid := range infoTypeNames {
		if strings.EqualFold(name, s) {
			return oid, nil
		}
	}
	var oid asn1.ObjectIdentifier
	for part := range strings.SplitSeq(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || strconv.Itoa(n) != part {
			return nil, fmt.Errorf("%q is not an info type name or a dotted OID", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("%q is not an info type name or a dotted OID", s)
	}
	return oid, nil
}

// newRawGenMCommand returns cmp genm raw.
func newRawGenMCommand() *cobra.Command {
	o := &genmOptions{}
	cmd := &cobra.Command{
		Use:   "raw --server URL INFOTYPE... [flags]",
		Short: "Send a general message with any info types",
		Long: "Send a general message that asks for the given info types, by name such as caCerts or as dotted " +
			"OIDs, without a value, and list the items of the answer. RFC 9483 profiles one info type per message, " +
			"so some servers refuse more." + genmLong,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			items := make([]pkicmp.InfoTypeAndValue, 0, len(args))
			for _, a := range args {
				oid, err := parseInfoType(a)
				if err != nil {
					return err
				}
				items = append(items, pkicmp.InfoTypeAndValue{InfoType: oid})
			}
			answer, _, err := exchange(cmd.Context(), &o.connection, &o.protection, cmd.InOrStdin(), cmd.ErrOrStderr(),
				func(ctx context.Context, c *client.Client, pr *protected) ([]pkicmp.InfoTypeAndValue, error) {
					return c.SendGenM(ctx, items, pr.creds, pr.reqOpts...)
				})
			if err != nil || o.quiet {
				return err
			}
			w := reportWriter(cmd.OutOrStdout(), cmd.ErrOrStderr())
			ui.Report(w, true, "The answer holds "+count(len(answer), "item", "items"), nil)
			for _, item := range answer {
				ui.Section(w, infoTypeName(item.InfoType), []ui.Field{
					{Name: "OID", Value: item.InfoType.String()},
					{Name: "Value", Value: describeValue(item.InfoValue)},
				})
			}
			return nil
		},
	}
	o.addFlags(cmd, "")
	return cmd
}

// describeValue shows the size and the start of a DER value.
func describeValue(der []byte) string {
	if len(der) == 0 {
		return "absent"
	}
	const preview = 24
	if len(der) <= preview {
		return fmt.Sprintf("%d bytes %s", len(der), hex.EncodeToString(der))
	}
	return fmt.Sprintf("%d bytes %s...", len(der), hex.EncodeToString(der[:preview]))
}
