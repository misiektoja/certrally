package cli

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	est "github.com/misiektoja/go-pki-est"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// estCACertsOptions holds the est cacerts command line.
type estCACertsOptions struct {
	estConnection
	estAuth
	outputOptions
	out         string
	force       bool
	bootstrap   bool
	fingerprint string
}

// newESTCACertsCommand returns est cacerts.
func newESTCACertsCommand() *cobra.Command {
	o := &estCACertsOptions{}
	cmd := &cobra.Command{
		Use:   "cacerts --server URL [flags]",
		Short: "Get the CA certificates from an EST server",
		Long: "Get the current CA certificates from an EST server (RFC 7030 section 4.1).\n\n" +
			"When nothing can verify the server yet, --bootstrap connects without checking its TLS certificate " +
			"(RFC 7030 section 4.1.1). Compare a fingerprint with one the CA publishes, then pass it with " +
			"--fingerprint or confirm it when asked. Otherwise the certificates are not saved. If the CA issued " +
			"the TLS certificate of the server, later commands can trust the saved certificates with " +
			"--tls-ca-cert. A TLS-SRP sign-in with --srp authenticates the server without a certificate.\n\n" +
			estExitStatusHelp,
		Example: "  certrally est cacerts --server https://est.example.com --out ca.pem\n" +
			"  certrally est cacerts --server https://est.example.com --bootstrap \\\n" +
			"    --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --out ca.pem",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runESTCACerts(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.estConnection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange")
	o.estAuth.addFlags(cmd, "sign in with this TLS client certificate file, which may include the chain", false)
	o.outputOptions.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.out, "out", "", "write the certificates to this file, or - for standard output")
	f.BoolVar(&o.force, "force", false, "replace an existing --out file")
	f.BoolVar(&o.bootstrap, "bootstrap", false, "connect without checking the TLS certificate of the server")
	f.StringVar(&o.fingerprint, "fingerprint", "", "hex SHA-256 fingerprint that one of the certificates must have")
	cmd.MarkFlagsMutuallyExclusive("bootstrap", flagTLSCACert)
	cmd.MarkFlagsMutuallyExclusive("bootstrap", flagInsecure)
	cmd.MarkFlagsMutuallyExclusive("bootstrap", "srp")
	_ = cmd.RegisterFlagCompletionFunc("fingerprint", cobra.NoFileCompletions)
	return cmd
}

// parseFingerprint decodes a SHA-256 fingerprint written as hex, with optional colons or spaces.
func parseFingerprint(s string) ([]byte, error) {
	compact := strings.NewReplacer(":", "", " ", "").Replace(s)
	fp, err := hex.DecodeString(compact)
	if err != nil || len(fp) != sha256.Size {
		return nil, fmt.Errorf("--fingerprint %q is not a SHA-256 fingerprint of 64 hex digits", s)
	}
	return fp, nil
}

// Ways est cacerts checked the certificates, as in the JSON result.
const (
	verifiedTLS         = "tls"
	verifiedSRP         = "srp"
	verifiedFingerprint = "fingerprint"
	verifiedConfirmed   = "confirmed"
	verifiedNone        = "none"
)

// validate checks the command line and returns the --fingerprint value, which is nil without it.
// Before anything is fetched, it checks that bootstrapped certificates can be checked before they
// are saved.
func (o *estCACertsOptions) validate(p *printer, stdin io.Reader) ([]byte, error) {
	if err := o.estConnection.validate(); err != nil {
		return nil, err
	}
	if err := o.estAuth.validate(); err != nil {
		return nil, err
	}
	var fingerprint []byte
	if o.fingerprint != "" {
		fp, err := parseFingerprint(o.fingerprint)
		if err != nil {
			return nil, err
		}
		fingerprint = fp
	}
	if err := o.checkStdout(o.out); err != nil {
		return nil, err
	}
	if err := o.checkCapture(o.out); err != nil {
		return nil, err
	}
	if err := checkOutputs(o.force, o.out); err != nil {
		return nil, err
	}
	if o.bootstrap && o.out != "" && fingerprint == nil && !(p.text() && wizardTerminal(stdin, p.stderr)) {
		return nil, errors.New("--bootstrap saves the certificates only after a check. Pass the fingerprint the CA " +
			"published with --fingerprint, or run on a terminal to confirm it")
	}
	return fingerprint, nil
}

// runESTCACerts performs est cacerts.
func runESTCACerts(ctx context.Context, o *estCACertsOptions, p *printer, stdin io.Reader) error {
	fingerprint, err := o.validate(p, stdin)
	if err != nil {
		return err
	}
	o.unverified = o.bootstrap

	certs, s, err := estRun(ctx, &o.estConnection, &o.estAuth, stdin, p, false,
		func(ctx context.Context, s *estSession) ([]*x509.Certificate, error) {
			return s.client.CACerts(ctx)
		})
	if err != nil {
		return err
	}
	result := &estCACertsJSON{Certificates: certificatesResult(certs), Saved: []string{}, Verified: verifiedTLS}
	switch {
	case o.bootstrap, o.insecure:
		result.Verified = verifiedNone
	case o.srp:
		result.Verified = verifiedSRP
	}
	if fingerprint != nil {
		if matchFingerprint(certs, fingerprint) == nil {
			s.p.doc.Result = result
			err := fmt.Errorf("none of the %s has the SHA-256 fingerprint %x",
				count(len(certs), "certificate", "certificates"), fingerprint)
			ferr := s.p.fail(&failure{
				code:    exitProtocol,
				Title:   "No CA certificate has the expected fingerprint",
				Message: err.Error(),
				Hint:    "Do not trust these certificates. Check --fingerprint against the one the CA published.",
			}, err)
			listCACerts(p, certs)
			return ferr
		}
		result.Verified = verifiedFingerprint
	}

	listed := false
	if o.bootstrap && o.out != "" && fingerprint == nil {
		ui.Heading(p.stderr, "Check the fingerprints before trusting these certificates", "")
		for _, cert := range certs {
			ui.Section(p.stderr, ui.Sanitize(dn.Format(cert.RawSubject)), caCertFields(cert))
		}
		listed = true
		ok, err := newAsker(ctx, stdin, p.stderr).confirm("Does a SHA-256 fingerprint match the one the CA published?", false)
		if err != nil && !errors.Is(err, errEnrollCancelled) {
			return err
		}
		if !ok {
			return errors.New("the certificates were not saved, because no fingerprint was confirmed")
		}
		result.Verified = verifiedConfirmed
	}

	if o.out != "" {
		if err := writeData(o.out, pemfile.EncodeCertificates(certs), 0o644, o.force, p.stdout); err != nil {
			return err
		}
		result.Saved = savedPaths(o.out)
	}
	fields := []ui.Field{{Name: fieldVerified, Value: verifiedText(result.Verified, certs, fingerprint, o.skipFlag())}}
	fields = append(fields, s.serverCertificateFields(certs)...)
	fields = append(fields, ui.Field{Name: fieldSaved, Value: strings.Join(result.Saved, ", ")})
	switch {
	case result.Verified == verifiedNone && len(result.Saved) > 0:
		fields = append(fields, ui.Field{
			Name:  fieldNote,
			Value: "Check a fingerprint with the CA before trusting the saved certificates.",
		})
	case result.Verified == verifiedNone:
		fields = append(fields, ui.Field{
			Name:  fieldNote,
			Value: "Check a fingerprint with the CA, then save the certificates with --fingerprint and --out.",
		})
	}
	if tls := s.lastTLS(); tls != nil && len(tls.ServerCertificates) > 0 {
		issued := chainsToCerts(tls.ServerCertificates, certs)
		result.TLSIssued = &issued
	}
	p.result("Received "+count(len(certs), "CA certificate", "CA certificates"), fields, result)
	if !listed {
		listCACerts(p, certs)
	}
	return nil
}

// listCACerts adds a section for each certificate below the report.
func listCACerts(p *printer, certs []*x509.Certificate) {
	for _, cert := range certs {
		p.section(ui.Sanitize(dn.Format(cert.RawSubject)), caCertFields(cert))
	}
}

// matchFingerprint returns the certificate with the SHA-256 fingerprint fp, or nil.
func matchFingerprint(certs []*x509.Certificate, fp []byte) *x509.Certificate {
	for _, cert := range certs {
		if sum := sha256.Sum256(cert.Raw); string(sum[:]) == string(fp) {
			return cert
		}
	}
	return nil
}

// skipFlag names the flag that skipped the check of the server certificate.
func (o *estCACertsOptions) skipFlag() string {
	if o.bootstrap {
		return "--bootstrap"
	}
	return "--" + flagInsecure
}

// verifiedText describes how the certificates were checked. skipFlag names the flag that skipped
// the check when verified is verifiedNone.
func verifiedText(verified string, certs []*x509.Certificate, fp []byte, skipFlag string) string {
	switch verified {
	case verifiedFingerprint:
		subject := dn.Format(matchFingerprint(certs, fp).RawSubject)
		return "the fingerprint of " + ui.Sanitize(subject) + " matches --fingerprint"
	case verifiedConfirmed:
		return "fingerprint confirmed"
	case verifiedNone:
		return "no, " + skipFlag + " did not check the server"
	case verifiedSRP:
		return "the TLS-SRP sign-in, in which the server proved it holds the verifier of --user"
	}
	return "the TLS certificate of the server"
}

// lastTLS returns the connection of the last exchange, or nil.
func (s *estSession) lastTLS() *trace.TLSInfo {
	for _, ev := range slices.Backward(s.recorder.Events()) {
		if ev.Kind == trace.Connect {
			return ev.TLS
		}
	}
	return nil
}

// estCSRAttrsOptions holds the est csrattrs command line.
type estCSRAttrsOptions struct {
	estConnection
	estAuth
	outputOptions
}

// newESTCSRAttrsCommand returns est csrattrs.
func newESTCSRAttrsCommand() *cobra.Command {
	o := &estCSRAttrsOptions{}
	cmd := &cobra.Command{
		Use:   "csrattrs --server URL [flags]",
		Short: "Ask an EST server what a certificate request should contain",
		Long: "Get the CSR attributes of an EST server (RFC 7030 section 4.5): the attributes, extensions and " +
			"key types the CA wants in a certificate request.\n\n" + estExitStatusHelp,
		Example: "  certrally est csrattrs --server https://est.example.com",
		Args:    cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			if err := o.estConnection.validate(); err != nil {
				return err
			}
			if err := o.estAuth.validate(); err != nil {
				return err
			}
			attrs, _, err := estRun(cmd.Context(), &o.estConnection, &o.estAuth, cmd.InOrStdin(), p, false,
				func(ctx context.Context, s *estSession) (est.CSRAttrs, error) {
					return s.client.CSRAttrs(ctx)
				})
			if err != nil {
				return err
			}
			reportCSRAttrs(p, attrs)
			return nil
		}),
	}
	o.estConnection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange")
	o.estAuth.addFlags(cmd, "sign in with this TLS client certificate file, which may include the chain", false)
	o.outputOptions.addFlags(cmd)
	return cmd
}

// reportCSRAttrs reports the CSR attributes of a server.
func reportCSRAttrs(p *printer, attrs est.CSRAttrs) {
	result := &csrAttrsJSON{}
	var fields []ui.Field
	result.Attributes, fields = csrAttrsResult(attrs)
	if len(result.Attributes) == 0 {
		p.result("The CA asks for no particular attributes", nil, result)
		return
	}
	p.result("The CA asks for "+count(len(result.Attributes), "attribute", "attributes"), fields, result)
}

// csrAttrsResult returns the JSON and text forms of CSR attributes.
func csrAttrsResult(attrs est.CSRAttrs) ([]csrAttrJSON, []ui.Field) {
	n := len(attrs.OIDs) + len(attrs.Attributes)
	result, fields := make([]csrAttrJSON, 0, n), make([]ui.Field, 0, n)
	for _, oid := range attrs.OIDs {
		result = append(result, csrAttrJSON{OID: oid.String(), Name: oidName(oid)})
		fields = append(fields, ui.Field{Name: oidLabel(oid), Value: "requested"})
	}
	for _, attr := range attrs.Attributes {
		j := csrAttrJSON{OID: attr.Type.String(), Name: oidName(attr.Type), Values: []string{}}
		var texts []string
		for _, v := range attr.Values {
			value, text := attrValue(v)
			j.Values = append(j.Values, value)
			texts = append(texts, text)
		}
		result = append(result, j)
		fields = append(fields, ui.Field{Name: oidLabel(attr.Type), Value: ui.Sanitize(strings.Join(texts, ", "))})
	}
	return result, fields
}

// csrAttrNames maps the OIDs that CSR attributes commonly carry to display names.
var csrAttrNames = map[string]string{
	"1.2.840.113549.1.9.7":  "challengePassword",
	"1.2.840.113549.1.9.14": "extensionRequest",
	"1.2.840.10045.2.1":     "ecPublicKey",
	"1.2.840.113549.1.1.1":  "rsaEncryption",
	"2.5.4.3":               "commonName",
	"2.5.4.5":               "serialNumber",
	"2.5.4.10":              "organizationName",
	"2.5.4.11":              "organizationalUnitName",
	"2.5.4.6":               "countryName",
	"1.2.840.113549.1.9.1":  "emailAddress",
	"1.3.6.1.1.1.1.22":      "macAddress",
}

// oidName returns the name of an OID in a CSR attribute, or "" when certrally knows none.
func oidName(oid asn1.ObjectIdentifier) string {
	s := oid.String()
	for _, names := range []map[string]string{csrAttrNames, curveNames, extensionNames} {
		if name, ok := names[s]; ok {
			return name
		}
	}
	if name := trace.AlgorithmName(oid); name != s {
		return name
	}
	return ""
}

// oidLabel returns the name of an OID followed by the OID, or the OID alone.
func oidLabel(oid asn1.ObjectIdentifier) string {
	if name := oidName(oid); name != "" {
		return name + " (" + oid.String() + ")"
	}
	return oid.String()
}

// attrValue returns a value of a CSR attribute for JSON and for the text report. OIDs are dotted,
// an extension request lists its extensions and values that are neither text nor numbers are base64
// DER.
func attrValue(v any) (value, text string) {
	switch x := v.(type) {
	case asn1.ObjectIdentifier:
		return x.String(), oidLabel(x)
	case asn1.RawValue:
		var exts []pkix.Extension
		if rest, err := asn1.Unmarshal(x.FullBytes, &exts); err == nil && len(rest) == 0 && len(exts) > 0 {
			oids, names := make([]string, len(exts)), make([]string, len(exts))
			for i, e := range exts {
				oids[i], names[i] = e.Id.String(), extensionName(e.Id)
			}
			return strings.Join(oids, ","), strings.Join(names, ", ")
		}
		return base64.StdEncoding.EncodeToString(x.FullBytes), count(len(x.FullBytes), "byte", "bytes")
	default:
		s := fmt.Sprint(x)
		return s, s
	}
}
