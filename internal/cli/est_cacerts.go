package cli

import (
	"bytes"
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
	"strconv"
	"strings"
	"time"

	est "github.com/misiektoja/go-pki-est"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
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
	format      outFormat
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
			"--fingerprint or confirm it when asked. The certificate with that fingerprint is saved together " +
			"with the certificates it issued. The other certificates of the response are not saved. If the CA " +
			"issued the TLS certificate of the server, later commands can trust the saved certificates with " +
			"--tls-ca-cert. The request needs no credentials, so --bootstrap refuses the flags that sign in, " +
			"which would send them to the unchecked server. A TLS-SRP sign-in with --srp authenticates the " +
			"server without a certificate.\n\n" +
			estExitStatusHelp,
		Example: "  certrally est cacerts --server https://est.example.com --out ca.pem\n" +
			"  certrally est cacerts --server https://est.example.com --bootstrap \\\n" +
			"    --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --out ca.pem",
		Args: o.noArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runESTCACerts(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.estConnection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange")
	o.estAuth.addFlags(cmd, "sign in with this TLS client certificate file, which may include the chain", false)
	o.outputOptions.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.out, "out", "", "write the certificates to this file, or - for standard output")
	o.format.addFlags(cmd, formatPEM, outFormatCertsHelp)
	f.BoolVar(&o.force, "force", false, "replace an existing --out file")
	f.BoolVar(&o.bootstrap, "bootstrap", false, "connect without checking the TLS certificate of the server")
	f.StringVar(&o.fingerprint, "fingerprint", "",
		"hex SHA-256 fingerprint of the certificate to trust, which is saved with the certificates it issued")
	cmd.MarkFlagsMutuallyExclusive("bootstrap", flagTLSCACert)
	cmd.MarkFlagsMutuallyExclusive("bootstrap", flagInsecure)
	cmd.MarkFlagsMutuallyExclusive("bootstrap", "srp")
	// The cacerts request needs no sign-in (RFC 7030 section 4.1.2), and go-pki-est would send the
	// credentials on it to a server that nothing checked.
	for _, credential := range []string{"user", flagPassword, "password-file", flagToken, flagTokenFile} {
		cmd.MarkFlagsMutuallyExclusive("bootstrap", credential)
	}
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
	if err := o.format.validate(); err != nil {
		return nil, err
	}
	if err := o.checkStdout(o.out); err != nil {
		return nil, err
	}
	if err := o.checkCapture(o.out); err != nil {
		return nil, err
	}
	if err := p.confirmOutputs(&o.force, o.out); err != nil {
		return nil, err
	}
	if o.bootstrap && o.out != "" && fingerprint == nil && !(p.text() && wizardTerminal(stdin, p.terminal)) {
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
	// matched is the certificate a fingerprint check covers. The check also covers the certificates
	// that chain to it. The rest of the response stays unverified and is not saved, since anyone who
	// answered the unchecked connection could have added it.
	var matched *x509.Certificate
	if fingerprint != nil {
		matched = matchFingerprint(certs, fingerprint)
		if matched == nil {
			s.p.doc.Result = result
			err := fmt.Errorf("none of the %s has the SHA-256 fingerprint %x",
				count(len(certs), "certificate", "certificates"), fingerprint)
			ferr := s.p.fail(&failure{
				code:    exitProtocol,
				Title:   "No CA certificate has the expected fingerprint",
				Message: err.Error(),
				Hint:    "Do not trust these certificates. Check --fingerprint against the one the CA published.",
			}, err)
			listCACerts(p, certs, nil)
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
		if matched, err = confirmFingerprint(ctx, stdin, p, certs); err != nil {
			return err
		}
		result.Verified = verifiedConfirmed
	}

	trusted, unverified := certs, []*x509.Certificate(nil)
	if matched != nil {
		trusted, unverified = coveredBy(certs, matched)
		result.Unverified = certificatesResult(unverified)
		for _, cert := range unverified {
			p.warn(ui.Sanitize(dn.Format(cert.RawSubject)) + " was not saved: it neither has the checked fingerprint " +
				"nor was issued by the certificate that has it.")
		}
	}

	if o.out != "" {
		data, err := o.format.certificates(trusted)
		if err != nil {
			return err
		}
		if err := writeData(o.out, data, 0o644, o.force, p.stdout); err != nil {
			return err
		}
		result.Saved = savedPaths(o.out)
	}
	fields := []ui.Field{{Name: fieldVerified, Value: verifiedText(result.Verified, matched, o.skipFlag())}}
	fields = append(fields, s.serverCertificateFields(trusted)...)
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
		issued := chainsToCerts(tls.ServerCertificates, trusted)
		result.TLSIssued = &issued
	}
	p.result("Received "+count(len(certs), "CA certificate", "CA certificates"), fields, result)
	if !listed {
		listCACerts(p, certs, unverified)
	}
	return nil
}

// errNoFingerprintConfirmed reports that a bootstrap ended without a confirmed fingerprint.
var errNoFingerprintConfirmed = errors.New("the certificates were not saved, because no fingerprint was confirmed")

// confirmFingerprint asks which of certs has the fingerprint the CA published and returns it. A
// single certificate gets a yes or no question. A cancelled question counts as no.
func confirmFingerprint(ctx context.Context, stdin io.Reader, p *printer, certs []*x509.Certificate) (*x509.Certificate, error) {
	ask := newAsker(ctx, stdin, p.terminal)
	if len(certs) == 1 {
		ok, err := ask.confirm("Does the SHA-256 fingerprint match the one the CA published?", false)
		if err != nil && !errors.Is(err, errEnrollCancelled) {
			return nil, err
		}
		if !ok {
			return nil, errNoFingerprintConfirmed
		}
		return certs[0], nil
	}
	choices := make([]choice, 0, len(certs)+1)
	for i, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		label := ui.Sanitize(dn.Format(cert.RawSubject)) + "  " + hexBytes(sum[:4]) + "..."
		choices = append(choices, choice{label: label, value: strconv.Itoa(i)})
	}
	choices = append(choices, choice{label: "None of them", value: ""})
	answer, err := ask.choose("Which certificate has the SHA-256 fingerprint the CA published?",
		"That certificate and the certificates it issued are saved.", choices, "")
	if err != nil && !errors.Is(err, errEnrollCancelled) {
		return nil, err
	}
	i, convErr := strconv.Atoi(answer)
	if err != nil || convErr != nil || i < 0 || i >= len(certs) {
		return nil, errNoFingerprintConfirmed
	}
	return certs[i], nil
}

// coveredBy splits certs into those that a fingerprint check of matched covers, in the order of
// certs, and the rest. The check covers matched and every certificate whose signatures chain to it.
func coveredBy(certs []*x509.Certificate, matched *x509.Certificate) (covered, rest []*x509.Certificate) {
	trusted := map[*x509.Certificate]bool{matched: true}
	for grown := true; grown; {
		grown = false
		for _, cert := range certs {
			if trusted[cert] {
				continue
			}
			for issuer := range trusted {
				if bytes.Equal(cert.RawIssuer, issuer.RawSubject) && signedBy(cert, issuer) {
					trusted[cert], grown = true, true
					break
				}
			}
		}
	}
	for _, cert := range certs {
		if trusted[cert] {
			covered = append(covered, cert)
		} else {
			rest = append(rest, cert)
		}
	}
	return covered, rest
}

// listCACerts adds a section for each certificate below the report and marks those in unverified
// as not saved.
func listCACerts(p *printer, certs, unverified []*x509.Certificate) {
	for _, cert := range certs {
		fields := caCertFields(cert)
		if slices.Contains(unverified, cert) {
			fields = append(fields, ui.Field{Name: fieldNote, Value: "not saved, nothing verified it"})
		}
		p.section(ui.Sanitize(dn.Format(cert.RawSubject)), fields)
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

// verifiedText describes how the certificates were checked. matched is the certificate whose
// fingerprint was checked, if any. skipFlag names the flag that skipped the check when verified is
// verifiedNone.
func verifiedText(verified string, matched *x509.Certificate, skipFlag string) string {
	switch verified {
	case verifiedFingerprint:
		return "the fingerprint of " + ui.Sanitize(dn.Format(matched.RawSubject)) + " matches --fingerprint"
	case verifiedConfirmed:
		return "the fingerprint of " + ui.Sanitize(dn.Format(matched.RawSubject)) + " was confirmed"
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
		Args:    o.noArgs,
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
