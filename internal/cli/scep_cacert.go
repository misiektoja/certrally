package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 fingerprints identify CA certificates, as RFC 8894 section 2.2 allows.
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pkcs7"
	"github.com/misiektoja/go-pki-scep/scepclient"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/ui"
)

// scepCapsOptions holds the scep caps command line.
type scepCapsOptions struct {
	scepConnection
	outputOptions
}

// newSCEPCapsCommand returns scep caps.
func newSCEPCapsCommand() *cobra.Command {
	o := &scepCapsOptions{}
	cmd := &cobra.Command{
		Use:   "caps --server URL [flags]",
		Short: "List the capabilities of a SCEP server",
		Long: "Send GetCACaps (RFC 8894 section 3.5) and list the capabilities of the server, with the digest, " +
			"cipher and HTTP method that certrally picks from them.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep caps --server http://scep.example.com/scep --ca 'Issuing CA'",
		Args:    cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			if err := o.scepConnection.validate(); err != nil {
				return err
			}
			caps, _, err := scepRun(cmd.Context(), &o.scepConnection, p,
				func(ctx context.Context, s *scepSession) (scepclient.Capabilities, error) {
					return s.client.GetCACaps(ctx)
				})
			if err != nil {
				return err
			}
			reportSCEPCaps(p, caps)
			return nil
		}),
	}
	o.scepConnection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange", false)
	o.outputOptions.addFlags(cmd)
	return cmd
}

// scepChoice is what certrally sends to a server with the given capabilities.
type scepChoice struct {
	digest, cipher, method string
}

// scepDefaults returns the digest, cipher and HTTP method that go-pki-scep picks from caps when the
// command line names none: SHA-256 when it is listed, when SCEPStandard is listed or when no digest
// is listed, otherwise SHA-512 or SHA-1, AES-128-CBC unless only DES3 is listed and POST when
// POSTPKIOperation or SCEPStandard is listed.
func scepDefaults(caps scepclient.Capabilities) scepChoice {
	c := scepChoice{digest: crypto.SHA256.String(), cipher: pkcs7.AES128CBC.String(), method: http.MethodGet}
	standard := caps.Has("SCEPStandard")
	switch {
	case caps.Has("SHA-256") || standard:
	case caps.Has("SHA-512"):
		c.digest = crypto.SHA512.String()
	case caps.Has("SHA-1"):
		c.digest = crypto.SHA1.String()
	}
	if caps.Has("DES3") && !caps.Has("AES") && !standard {
		c.cipher = pkcs7.DESEDE3CBC.String()
	}
	if caps.Has("POSTPKIOperation") || standard {
		c.method = http.MethodPost
	}
	return c
}

// reportSCEPCaps reports the capabilities of a server.
func reportSCEPCaps(p *printer, caps scepclient.Capabilities) {
	choice := scepDefaults(caps)
	result := &scepCapsJSON{
		Capabilities: append([]string{}, caps...),
		Digest:       choice.digest,
		Cipher:       choice.cipher,
		Method:       choice.method,
		Renewal:      caps.Has("Renewal"),
		NextCACert:   caps.Has("GetNextCACert"),
	}
	title := "The server lists " + count(len(caps), "capability", "capabilities")
	if len(caps) == 0 {
		title = "The server lists no capabilities"
	}
	p.result(title, []ui.Field{
		{Name: "Capabilities", Value: ui.Sanitize(strings.Join(caps, ", "))},
		{Name: "Signs with", Value: choice.digest},
		{Name: "Encrypts with", Value: choice.cipher},
		{Name: "Sends requests with", Value: "HTTP " + choice.method},
		{Name: "Renewal", Value: yesNo(result.Renewal)},
		{Name: "Next CA certificate", Value: yesNo(result.NextCACert)},
	}, result)
}

// yesNo returns "yes" or "no".
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// scepCertsOptions holds the command line of scep cacert, scep chain and scep nextca.
type scepCertsOptions struct {
	scepConnection
	scepTrust
	outputOptions
	out    string
	force  bool
	format outFormat
}

// addFlags registers the flags of a command that gets certificates. trusted adds --ca-cert, which
// only scep nextca uses.
func (o *scepCertsOptions) addFlags(cmd *cobra.Command, trusted bool) {
	o.scepConnection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange", false)
	o.outputOptions.addFlags(cmd)
	if trusted {
		o.scepTrust.addFlags(cmd)
	} else {
		cmd.Flags().StringVar(&o.fingerprint, flagFingerprint, "",
			"hex SHA-256 or SHA-1 fingerprint of the certificate to trust, which is saved with the certificates it issued")
		_ = cmd.RegisterFlagCompletionFunc(flagFingerprint, cobra.NoFileCompletions)
	}
	f := cmd.Flags()
	f.StringVar(&o.out, "out", "", "write the certificates to this file, or - for standard output")
	o.format.addFlags(cmd, formatPEM, outFormatCertsHelp)
	f.BoolVar(&o.force, "force", false, "replace an existing --out file")
}

// validate checks the command line and returns the --fingerprint value, which is nil without it.
func (o *scepCertsOptions) validate(p *printer) ([]byte, error) {
	if err := o.scepConnection.validate(); err != nil {
		return nil, err
	}
	fp, err := o.fingerprintBytes()
	if err != nil {
		return nil, err
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
	return fp, p.confirmOutputs(&o.force, o.out)
}

// newSCEPCACertCommand returns scep cacert.
func newSCEPCACertCommand() *cobra.Command {
	o := &scepCertsOptions{}
	cmd := &cobra.Command{
		Use:   "cacert --server URL [flags]",
		Short: "Get the CA and RA certificates from a SCEP server",
		Long: "Send GetCACert (RFC 8894 section 4.2) and show the CA certificate and any RA certificates with " +
			"their fingerprints.\n\n" +
			"Compare a fingerprint with one the CA publishes, then save the certificates with --fingerprint and " +
			"--out. The certificate with that fingerprint is saved together with the certificates it issued. The " +
			"other certificates of the answer are not saved. Later commands can trust the saved file with " +
			"--ca-cert instead of asking the server again.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep cacert --server http://scep.example.com/scep --ca 'Issuing CA'\n" +
			"  certrally scep cacert --server http://scep.example.com/scep --ca 'Issuing CA' \\\n" +
			"    --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 --out ca.pem",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			fp, err := o.validate(p)
			if err != nil {
				return err
			}
			certs, s, err := scepRun(cmd.Context(), &o.scepConnection, p,
				func(ctx context.Context, s *scepSession) (*scepclient.CACertificates, error) {
					return s.client.GetCACert(ctx)
				})
			if err != nil {
				return err
			}
			return o.report(s, certs.All, certs, fp, "Received "+count(len(certs.All), "certificate", "certificates"))
		}),
	}
	o.addFlags(cmd, false)
	return cmd
}

// newSCEPChainCommand returns scep chain.
func newSCEPChainCommand() *cobra.Command {
	o := &scepCertsOptions{}
	cmd := &cobra.Command{
		Use:   "chain --server URL [flags]",
		Short: "Get the CA certificate and the certificates that issued it",
		Long: "Send GetCACertChain and show the CA certificate followed by the certificates that issued it, up to " +
			"the root, in the order of the server. RFC 8894 does not define the operation, but some CAs serve it. " +
			"--fingerprint and --out work as in certrally scep cacert, so a fingerprint of the root saves the " +
			"whole chain.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep chain --server http://scep.example.com/scep --ca 'Issuing CA' --out chain.pem",
		Args:    cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			fp, err := o.validate(p)
			if err != nil {
				return err
			}
			chain, s, err := scepRun(cmd.Context(), &o.scepConnection, p,
				func(ctx context.Context, s *scepSession) ([]*x509.Certificate, error) {
					return s.client.GetCACertChain(ctx)
				})
			if err != nil {
				return err
			}
			for i := 0; i+1 < len(chain); i++ {
				if !bytes.Equal(chain[i].RawIssuer, chain[i+1].RawSubject) {
					p.warn(ui.Sanitize(dn.Format(chain[i].RawSubject)) + " is not issued by the next certificate of the chain.")
				}
			}
			return o.report(s, chain, nil, fp, "Received a chain of "+count(len(chain), "certificate", "certificates"))
		}),
	}
	o.addFlags(cmd, false)
	return cmd
}

// newSCEPNextCACommand returns scep nextca.
func newSCEPNextCACommand() *cobra.Command {
	o := &scepCertsOptions{}
	cmd := &cobra.Command{
		Use:   "nextca --server URL [flags]",
		Short: "Get the CA certificate that will replace the current one",
		Long: "Send GetNextCACert (RFC 8894 section 4.7) and show the CA and RA certificates that will replace the " +
			"current ones when the CA changes its key. The answer must be signed by the current CA or RA, which " +
			"come from --ca-cert or a GetCACert request.\n\n" +
			"Many servers have no next CA certificate until a CA key rollover is prepared. certrally then reports " +
			"none and exits with status 0 when the server answers without content or answers 404 Not Found while " +
			"GetCACert works at the same address. After a 404 with --ca-cert, certrally sends GetCACert to tell a " +
			"missing next CA certificate from a wrong path or CA name.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep nextca --server http://scep.example.com/scep --ca 'Issuing CA' --ca-cert ca.pem",
		Args:    cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			fp, err := o.validate(p)
			if err != nil {
				return err
			}
			pinned, err := o.loadPinned()
			if err != nil {
				return err
			}
			// none explains an answer without a next CA certificate.
			var none string
			next, s, err := scepRun(cmd.Context(), &o.scepConnection, p,
				func(ctx context.Context, s *scepSession) (*scepclient.CACertificates, error) {
					current, err := s.caCertificates(ctx, pinned, fp)
					if err != nil {
						return nil, err
					}
					next, err := s.client.GetNextCACert(ctx, current)
					if errors.Is(err, scepclient.ErrEmptyResponse) {
						none = "It answered without content, which some servers do when they lack GetNextCACert."
						return nil, nil
					}
					if httpErr, ok := errors.AsType[*scepclient.HTTPError](err); ok && httpErr.StatusCode == http.StatusNotFound {
						if err := s.confirmAddress(ctx); err != nil {
							return nil, err
						}
						none = "It answered 404 Not Found while GetCACert works at the same address, which servers do " +
							"until a CA key rollover is prepared."
						return nil, nil
					}
					return next, err
				})
			if err != nil {
				return err
			}
			if next == nil {
				p.result("The server announces no next CA certificate", []ui.Field{{Name: fieldNote, Value: none}},
					&scepCertsJSON{Certificates: []*scepCertJSON{}, Saved: []string{}, Verified: verifiedSigned})
				return nil
			}
			o.fingerprint = ""
			title := "Received " + count(len(next.All), "next CA certificate", "next CA certificates")
			return o.report(s, next.All, next, nil, title)
		}),
	}
	o.addFlags(cmd, true)
	return cmd
}

// confirmAddress checks that the server serves the CA at --server and --ca, so that a 404 answer to
// GetNextCACert means no next CA certificate rather than a wrong path or CA name. A session that
// trusted a GetCACert answer has shown that already. With --ca-cert it sends GetCACert.
func (s *scepSession) confirmAddress(ctx context.Context) error {
	if !s.pinned {
		return nil
	}
	_, err := s.client.GetCACert(ctx)
	return err
}

// verifiedSigned says that the current CA signed the next CA certificates, as in the JSON result.
const verifiedSigned = "signed"

// report saves and lists certs. sorted gives the roles of a GetCACert or GetNextCACert answer and is
// nil for a chain. fp is the --fingerprint value that the saved certificates must chain to. A
// GetNextCACert answer has no fp, because the current CA signed it.
func (o *scepCertsOptions) report(s *scepSession, certs []*x509.Certificate, sorted *scepclient.CACertificates, fp []byte, title string) error {
	p := s.p
	result := &scepCertsJSON{Saved: []string{}, Verified: verifiedNone}
	switch {
	case p.command == scepCommand+" nextca":
		result.Verified = verifiedSigned
	case !s.plainHTTP && !o.insecure:
		result.Verified = verifiedTLS
	}
	var matched *x509.Certificate
	trusted, unverified := certs, []*x509.Certificate(nil)
	if fp != nil {
		if matched = matchSCEPFingerprint(certs, fp); matched == nil {
			result.Certificates = scepCertsResult(certs, sorted)
			p.doc.Result = result
			err := &scepTrustError{err: errors.New("none of the " + count(len(certs), "certificate", "certificates") +
				" has the fingerprint " + o.fingerprint)}
			ferr := p.fail(&failure{
				code:    exitProtocol,
				Title:   "No certificate has the expected fingerprint",
				Message: err.Error(),
				Hint:    hintCheckFingerprint,
			}, err)
			listSCEPCerts(p, certs, sorted, nil)
			return ferr
		}
		result.Verified = verifiedFingerprint
		trusted, unverified = coveredBy(certs, matched)
		result.Unverified = scepCertsResult(unverified, sorted)
		for _, cert := range unverified {
			p.warn(ui.Sanitize(dn.Format(cert.RawSubject)) + " was not saved: it neither has the checked fingerprint " +
				"nor was issued by the certificate that has it.")
		}
	}
	result.Certificates = scepCertsResult(certs, sorted)
	if sorted != nil {
		result.CA = certificateResult(sorted.CA)
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
	fields := []ui.Field{}
	if sorted != nil {
		fields = append(fields, ui.Field{Name: "CA", Value: ui.Sanitize(dn.Format(sorted.CA.RawSubject))})
	}
	fields = append(fields,
		ui.Field{Name: fieldVerified, Value: scepVerifiedText(result.Verified, matched, s)},
		ui.Field{Name: fieldSaved, Value: strings.Join(result.Saved, ", ")},
	)
	if result.Verified == verifiedNone {
		note := "Check a fingerprint with the CA, then save the certificates with --fingerprint and --out."
		if len(result.Saved) > 0 {
			note = "Check a fingerprint with the CA before trusting the saved certificates."
		}
		fields = append(fields, ui.Field{Name: fieldNote, Value: note})
	}
	p.result(title, fields, result)
	listSCEPCerts(p, certs, sorted, unverified)
	return nil
}

// scepVerifiedText describes how the certificates were checked. matched is the certificate whose
// fingerprint was checked, if any.
func scepVerifiedText(verified string, matched *x509.Certificate, s *scepSession) string {
	switch verified {
	case verifiedFingerprint:
		return "the fingerprint of " + ui.Sanitize(dn.Format(matched.RawSubject)) + " matches --fingerprint"
	case verifiedSigned:
		return "signed by the current CA certificates"
	case verifiedTLS:
		return "the TLS certificate of the server"
	}
	if s.plainHTTP {
		return "no, plain HTTP does not authenticate the server"
	}
	return "no, --" + flagInsecure + " did not check the server"
}

// scepRoles names the roles a certificate has in a sorted GetCACert answer.
func scepRoles(cert *x509.Certificate, sorted *scepclient.CACertificates) []string {
	if sorted == nil {
		return nil
	}
	var roles []string
	if cert == sorted.CA {
		roles = append(roles, "issuing CA")
	}
	if slices.Contains(sorted.Recipients, cert) && cert != sorted.CA {
		roles = append(roles, "RA encryption")
	}
	if slices.Contains(sorted.Signers, cert) && cert != sorted.CA {
		roles = append(roles, "RA signature")
	}
	if len(roles) == 0 {
		roles = append(roles, "other")
	}
	return roles
}

// listSCEPCerts adds a section for each certificate below the report and marks those in unverified
// as not saved.
func listSCEPCerts(p *printer, certs []*x509.Certificate, sorted *scepclient.CACertificates, unverified []*x509.Certificate) {
	for _, cert := range certs {
		sum := sha1.Sum(cert.Raw) //nolint:gosec // G401: see the import.
		fields := caCertFields(cert)
		fields = append(fields, ui.Field{Name: fieldSHA1, Value: hexBytes(sum[:])})
		if roles := scepRoles(cert, sorted); roles != nil {
			fields = append(fields, ui.Field{Name: "Role", Value: strings.Join(roles, ", ")})
		}
		if slices.Contains(unverified, cert) {
			fields = append(fields, ui.Field{Name: fieldNote, Value: "not saved, nothing verified it"})
		}
		p.section(ui.Sanitize(dn.Format(cert.RawSubject)), fields)
	}
}

// scepCertsResult returns the JSON form of certs with their roles, never nil.
func scepCertsResult(certs []*x509.Certificate, sorted *scepclient.CACertificates) []*scepCertJSON {
	out := make([]*scepCertJSON, 0, len(certs))
	for _, cert := range certs {
		sum := sha1.Sum(cert.Raw) //nolint:gosec // G401: see the import.
		out = append(out, &scepCertJSON{
			certificateJSON: certificateResult(cert),
			SHA1:            hex.EncodeToString(sum[:]),
			Roles:           scepRoles(cert, sorted),
		})
	}
	return out
}
