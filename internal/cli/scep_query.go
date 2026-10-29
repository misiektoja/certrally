package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/misiektoja/go-scep/scepclient"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/ui"
)

// scepQueryOptions holds the command line of scep getcert and scep getcrl.
type scepQueryOptions struct {
	scepConnection
	scepTrust
	outputOptions
	keyPassword
	// crl selects GetCRL instead of GetCert.
	crl      bool
	certFile string
	keyFile  string
	serial   string
	issuer   string
	out      string
	force    bool
	format   outFormat
	hash     string
	cipher   string
}

// newSCEPGetCertCommand returns scep getcert.
func newSCEPGetCertCommand() *cobra.Command {
	o := &scepQueryOptions{}
	cmd := &cobra.Command{
		Use:   "getcert --server URL --serial SERIAL [flags]",
		Short: "Get a certificate that the CA issued by its serial number",
		Long: "Send GetCert (RFC 8894 section 3.3.4) for the certificate with serial number --serial and save it " +
			"with --out. The issuer is the CA certificate unless --issuer names another.\n\n" +
			"The request is signed with --cert and --key, which servers usually require to be a certificate the " +
			"CA issued and which must be RSA, or else with a temporary self-signed certificate.\n\n" +
			scepExitStatusHelp,
		Example: "  certrally scep getcert --server http://scep.example.com/scep --ca 'Issuing CA' \\\n" +
			"    --serial 0x1A2B --cert device.pem --key device.key --out found.pem",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runSCEPQuery(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addFlags(cmd, outFormatCertsHelp)
	_ = cmd.MarkFlagRequired("serial")
	return cmd
}

// newSCEPGetCRLCommand returns scep getcrl.
func newSCEPGetCRLCommand() *cobra.Command {
	o := &scepQueryOptions{crl: true}
	cmd := &cobra.Command{
		Use:   "getcrl --server URL [flags]",
		Short: "Get the CRL that covers a certificate",
		Long: "Send GetCRL (RFC 8894 section 3.3.4) for the certificate in --cert or the one with serial " +
			"number --serial and save the CRL with --out. The CRL signature is checked against the CA " +
			"certificate.\n\n" +
			"The request is signed with --cert and --key, which must be RSA, or else with a temporary self-signed " +
			"certificate.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep getcrl --server http://scep.example.com/scep --ca 'Issuing CA' \\\n" +
			"    --cert device.pem --key device.key --out ca.crl",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runSCEPQuery(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addFlags(cmd, outFormatOutHelp)
	return cmd
}

// addFlags registers the flags of scep getcert and scep getcrl.
func (o *scepQueryOptions) addFlags(cmd *cobra.Command, formatHelp string) {
	o.scepConnection.addFlags(cmd, 2*time.Minute, "limit for the whole exchange", false)
	o.addDecryptFlags(cmd)
	o.scepTrust.addFlags(cmd)
	o.outputOptions.addFlags(cmd)
	o.keyPassword.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.certFile, "cert", "", "sign the request with this certificate, which the CA issued")
	f.StringVar(&o.keyFile, "key", "", "the RSA private key of --cert")
	f.StringVar(&o.serial, "serial", "", "serial number of the certificate: decimal, 0x hex or colon-separated hex")
	f.StringVar(&o.issuer, "issuer", "",
		"issuer of the certificate, such as CN=Example CA, when it is not the CA certificate")
	f.StringVar(&o.out, "out", "", "write the answer to this file, or - for standard output")
	o.format.addFlags(cmd, formatPEM, formatHelp)
	f.BoolVar(&o.force, "force", false, "replace an existing --out file")
	f.StringVar(&o.hash, "hash", "", scepHashHelp)
	f.StringVar(&o.cipher, "cipher", "", "content cipher of the request: aes128, aes192, aes256, des3 or des, by default "+
		"aes128 unless the server lists only DES3")
	cmd.MarkFlagsRequiredTogether("cert", "key")
	for _, name := range []string{"serial", "issuer"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// validate checks flag combinations that cobra cannot express.
func (o *scepQueryOptions) validate(p *printer) error {
	if err := o.scepConnection.validate(); err != nil {
		return err
	}
	if _, err := o.fingerprintBytes(); err != nil {
		return err
	}
	if _, err := scepHash(o.hash); err != nil {
		return err
	}
	if _, err := scepCipher(o.cipher); err != nil {
		return err
	}
	if o.crl && o.serial == "" && o.certFile == "" {
		return errors.New("--serial or --cert names the certificate whose CRL to get")
	}
	if o.issuer != "" && o.serial == "" {
		return errors.New("--issuer needs --serial")
	}
	if err := o.format.validate(); err != nil {
		return err
	}
	if err := o.checkStdout(o.out); err != nil {
		return err
	}
	if err := o.checkCapture(o.out); err != nil {
		return err
	}
	return p.confirmOutputs(&o.force, o.out)
}

// queryRequest builds the GetCert or GetCRL request without its issuer default, which needs the CA
// certificate.
func (o *scepQueryOptions) queryRequest(stdin io.Reader, prompt io.Writer) (scepclient.QueryRequest, error) {
	var req scepclient.QueryRequest
	var err error
	if req.Digest, err = scepHash(o.hash); err != nil {
		return req, err
	}
	if req.Encryption.ContentEncryption, err = scepCipher(o.cipher); err != nil {
		return req, err
	}
	var own *x509.Certificate
	if o.certFile != "" {
		chain, err := pemfile.ReadCertificates(o.certFile)
		if err != nil {
			return req, err
		}
		own = chain[0]
		signer, err := o.keyPassword.loadSigner(o.keyFile, stdin, prompt)
		if err != nil {
			return req, err
		}
		if _, ok := signer.(*rsa.PrivateKey); !ok {
			return req, errors.New("--key must be an RSA key, because SCEP answers are encrypted for the key that signs")
		}
		if !publicKeyEqual(signer.Public(), own.PublicKey) {
			return req, errors.New("--key is not the key of the certificate in --cert")
		}
		req.SignerCertificate, req.SignerKey = own, signer
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return req, err
		}
		subject, err := dn.ParseName("CN=" + programName)
		if err != nil {
			return req, err
		}
		raw, err := asn1Name(subject)
		if err != nil {
			return req, err
		}
		if req.SignerCertificate, err = selfSignedSigner(raw, key); err != nil {
			return req, err
		}
		req.SignerKey = key
	}
	switch {
	case o.serial != "":
		if req.SerialNumber, err = parseSerial(o.serial); err != nil {
			return req, err
		}
		if o.issuer != "" {
			name, err := dn.ParseName(o.issuer)
			if err != nil {
				return req, errors.New("--issuer: " + err.Error())
			}
			if req.Issuer, err = asn1Name(name); err != nil {
				return req, err
			}
		}
	default:
		req.SerialNumber, req.Issuer = own.SerialNumber, own.RawIssuer
	}
	return req, nil
}

// runSCEPQuery performs scep getcert or scep getcrl.
func runSCEPQuery(ctx context.Context, o *scepQueryOptions, p *printer, stdin io.Reader) error {
	if err := o.validate(p); err != nil {
		return err
	}
	pinned, err := o.loadPinned()
	if err != nil {
		return err
	}
	fp, _ := o.fingerprintBytes()
	req, err := o.queryRequest(stdin, p.stderr)
	if err != nil {
		return err
	}
	type answer struct {
		certs []*x509.Certificate
		crl   []byte
	}
	got, s, err := scepRun(ctx, &o.scepConnection, p, func(ctx context.Context, s *scepSession) (answer, error) {
		ca, err := s.caCertificates(ctx, pinned, fp)
		if err != nil {
			return answer{}, err
		}
		if o.crl {
			crl, err := s.client.GetCRL(ctx, ca, req)
			return answer{crl: crl}, err
		}
		certs, err := s.client.GetCert(ctx, ca, req)
		return answer{certs: certs}, err
	})
	if err != nil {
		return err
	}
	if o.crl {
		crl, err := x509.ParseRevocationList(got.crl)
		if err != nil {
			return s.p.fail(&failure{code: exitProtocol, Title: "The answer holds no valid CRL", Message: err.Error()}, err)
		}
		return reportCRLContent(p, crl, s.ca.All, o.format, o.out, o.force, "")
	}
	return o.reportCertificates(s, got.certs, req.SerialNumber)
}

// reportCertificates saves and describes the certificates of a GetCert answer. The certificate with
// the requested serial number comes first.
func (o *scepQueryOptions) reportCertificates(s *scepSession, certs []*x509.Certificate, serial *big.Int) error {
	result := &scepGetCertJSON{Certificates: certificatesResult(certs), Saved: []string{}}
	if o.out != "" {
		data, err := o.format.certificates(certs)
		if err != nil {
			return err
		}
		if err := writeData(o.out, data, 0o644, o.force, s.p.stdout); err != nil {
			return err
		}
		result.Saved = savedPaths(o.out)
	}
	found := certs[0]
	for _, cert := range certs {
		if cert.SerialNumber != nil && cert.SerialNumber.Cmp(serial) == 0 {
			found = cert
			break
		}
	}
	if found.SerialNumber == nil || found.SerialNumber.Cmp(serial) != 0 {
		s.p.warn("No certificate of the answer has the requested serial number.")
	}
	fields := append(describeCertificate(found), ui.Field{Name: fieldSaved, Value: strings.Join(result.Saved, ", ")})
	s.p.result("Received "+count(len(certs), "certificate", "certificates"), fields, result)
	return nil
}

// asn1Name returns the DER encoding of a name.
func asn1Name(name pkix.Name) ([]byte, error) {
	return asn1.Marshal(name.ToRDNSequence())
}
