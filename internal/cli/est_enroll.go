package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// The EST operations that issue a certificate.
const (
	estEnroll       = "enroll"
	estReenroll     = "reenroll"
	estServerKeyGen = "serverkeygen"
)

// estEnrollOptions holds the command line of est enroll, est reenroll and est serverkeygen.
type estEnrollOptions struct {
	estConnection
	estAuth
	outputOptions
	// op is the command: estEnroll, estReenroll or estServerKeyGen.
	op        string
	subject   string
	sans      []string
	keyType   string
	newKey    string
	csr       string
	certOut   string
	keyOut    string
	force     bool
	tlsUnique bool
	format    outFormat
}

// estEnrollTimeoutHelp describes --timeout of the commands that issue a certificate.
const estEnrollTimeoutHelp = "limit for the whole exchange, including the waits the server asks for"

// newESTEnrollCommand returns est enroll.
func newESTEnrollCommand() *cobra.Command {
	o := &estEnrollOptions{op: estEnroll}
	cmd := &cobra.Command{
		Use:   "enroll --server URL --cert-out FILE [flags]",
		Short: "Request a certificate from an EST server",
		Long: "Request a certificate with a PKCS#10 request (RFC 7030 section 4.2.1) and save it.\n\n" +
			"A new key is generated unless --new-key or --csr supplies one. When the server answers that the " +
			"request is pending, certrally waits as long as its Retry-After header asks and sends the request " +
			"again, within --timeout.\n\n" + estExitStatusHelp,
		Example: "  certrally est enroll --server https://est.example.com --user device-42 \\\n" +
			"    --password-file password.txt --subject CN=device-42 --san device-42.example.com \\\n" +
			"    --cert-out device.pem --key-out device.key",
		Args: o.noArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runESTEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addCommonFlags(cmd, "sign in with this TLS client certificate file, which may include the chain", false)
	o.addNameFlags(cmd)
	o.addKeyFlags(cmd)
	return cmd
}

// newESTReenrollCommand returns est reenroll.
func newESTReenrollCommand() *cobra.Command {
	o := &estEnrollOptions{op: estReenroll}
	cmd := &cobra.Command{
		Use:   "reenroll --server URL --cert FILE --cert-out FILE [flags]",
		Short: "Renew a certificate with an EST server",
		Long: "Renew the certificate in --cert (RFC 7030 section 4.2.2) and save the new one. The request " +
			"repeats the subject and subjectAltName of that certificate.\n\n" +
			"With --key the certificate signs in over TLS. Without it, --user signs in with a password, as RFC " +
			"7030 section 2.3 allows when the certificate cannot be used for TLS. A new key is generated unless " +
			"--new-key or --csr supplies one. Pass the current key with --new-key to keep it.\n\n" + estExitStatusHelp,
		Example: "  certrally est reenroll --server https://est.example.com --cert device.pem --key device.key \\\n" +
			"    --cert-out device-new.pem --key-out device-new.key",
		Args: o.noArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runESTEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addCommonFlags(cmd, "the certificate to renew, which may include the chain", true)
	o.addKeyFlags(cmd)
	_ = cmd.MarkFlagRequired("cert")
	return cmd
}

// newESTServerKeyGenCommand returns est serverkeygen.
func newESTServerKeyGenCommand() *cobra.Command {
	o := &estEnrollOptions{op: estServerKeyGen}
	cmd := &cobra.Command{
		Use:   "serverkeygen --server URL --cert-out FILE --key-out FILE [flags]",
		Short: "Request a certificate and a key the server generates",
		Long: "Request a certificate for a key that the server generates and returns (RFC 7030 section 4.4) " +
			"and save both. certrally signs the request with a key of --key-type, which some servers copy for " +
			"the key they generate. It cannot decrypt a key the server encrypts.\n\n" + estExitStatusHelp,
		Example: "  certrally est serverkeygen --server https://est.example.com --user device-42 \\\n" +
			"    --subject CN=device-42 --cert-out device.pem --key-out device.key",
		Args: o.noArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runESTEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addCommonFlags(cmd, "sign in with this TLS client certificate file, which may include the chain", false)
	o.addNameFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.keyType, "key-type", keys.DefaultType,
		"type of the key that signs the request, such as ecdsa-p384 or ml-dsa-65")
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(keys.SigningTypeNames()))
	_ = cmd.MarkFlagRequired("key-out")
	return cmd
}

// addCommonFlags registers the connection, sign-in, output and file flags.
func (o *estEnrollOptions) addCommonFlags(cmd *cobra.Command, certHelp string, certAlone bool) {
	o.estConnection.addFlags(cmd, 5*time.Minute, estEnrollTimeoutHelp)
	o.estAuth.addFlags(cmd, certHelp, certAlone)
	o.outputOptions.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.certOut, "cert-out", "", "write the issued certificate to this file")
	f.StringVar(&o.keyOut, "key-out", "", "write the new private key to this file")
	f.BoolVar(&o.force, "force", false, "replace existing output files")
	o.format.addFlags(cmd, formatPEM, outFormatHelp)
	_ = cmd.MarkFlagRequired("cert-out")
}

// addNameFlags registers --subject and --san.
func (o *estEnrollOptions) addNameFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.subject, flagSubject, "", "subject name, such as CN=device-42,O=Example")
	f.StringArrayVar(&o.sans, flagSAN, nil, "subject alternative name: dns:, ip:, email: or uri: value (repeatable)")
	for _, name := range []string{flagSubject, flagSAN} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// addKeyFlags registers the flags that choose the key to certify.
func (o *estEnrollOptions) addKeyFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.keyType, "key-type", keys.DefaultType,
		"type of the generated key, such as ecdsa-p384, rsa-3072, ml-dsa-65 or mldsa65-ecdsa-p256-sha512")
	f.StringVar(&o.newKey, "new-key", "", "certify the private key in this file instead of generating one")
	f.StringVar(&o.csr, "csr", "", "send the PKCS#10 request in this file")
	f.BoolVar(&o.tlsUnique, "tls-unique", false,
		"bind the request to the TLS session with the tls-unique value (RFC 7030 section 3.5, TLS 1.2 only)")
	cmd.MarkFlagsMutuallyExclusive("key-type", "new-key", "csr")
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(keys.SigningTypeNames()))
}

// validate checks flag combinations that cobra cannot express.
func (o *estEnrollOptions) validate() error {
	if err := o.estConnection.validate(); err != nil {
		return err
	}
	if err := o.estAuth.validate(); err != nil {
		return err
	}
	switch {
	case o.op == estReenroll && o.keyFile == "" && o.user == "" && !o.tokenSelected():
		return errors.New("renewing without --key needs --user or --token, to sign in with a password or a token")
	case o.op == estEnroll && o.csr != "" && (o.subject != "" || len(o.sans) > 0):
		return errors.New("--subject and --san cannot change a request given with --csr")
	case o.op != estReenroll && o.csr == "" && o.subject == "" && len(o.sans) == 0:
		return errors.New("--subject or --san is required")
	case o.tlsUnique && o.csr != "":
		return errors.New("--tls-unique signs the request again, which needs its key. Use --new-key instead of --csr")
	}
	generated := o.op == estServerKeyGen || (o.csr == "" && o.newKey == "")
	switch {
	case generated && o.keyOut == "":
		return errors.New("--key-out is required to save the new key")
	case !generated && o.keyOut != "":
		return errors.New("--key-out is only used with a new key")
	}
	if err := o.format.validate(); err != nil {
		return err
	}
	if err := o.checkCapture(o.certOut, o.keyOut); err != nil {
		return err
	}
	return checkOutputs(o.force, o.certOut, o.keyOut)
}

// estRequest is a certificate request ready to send.
type estRequest struct {
	csr *x509.CertificateRequest
	// key is the key the request certifies. It is nil for --csr and signs only the request of a
	// serverkeygen.
	key crypto.Signer
}

// runESTEnroll performs est enroll, est reenroll or est serverkeygen.
func runESTEnroll(ctx context.Context, o *estEnrollOptions, p *printer, stdin io.Reader) error {
	if err := o.validate(); err != nil {
		return err
	}
	var renewed *x509.Certificate
	if o.op == estReenroll {
		chain, err := pemfile.ReadCertificates(o.certFile)
		if err != nil {
			return err
		}
		renewed = chain[0]
	}
	req, err := o.prepareRequest(renewed, stdin, p.stderr)
	if err != nil {
		return err
	}

	type issued struct {
		cert *x509.Certificate
		key  []byte
	}
	result, s, err := estRun(ctx, &o.estConnection, &o.estAuth, stdin, p, true,
		func(ctx context.Context, s *estSession) (issued, error) {
			if o.tlsUnique {
				s.client.SigningKey = req.key
			}
			switch o.op {
			case estReenroll:
				cert, err := s.client.Reenroll(ctx, req.csr)
				return issued{cert: cert}, err
			case estServerKeyGen:
				cert, key, err := s.client.ServerKeyGen(ctx, req.csr)
				return issued{cert: cert, key: key}, err
			default:
				cert, err := s.client.Enroll(ctx, req.csr)
				return issued{cert: cert}, err
			}
		})
	if err != nil {
		return err
	}
	if o.tlsUnique {
		s.warnTLSUnique()
	}
	keyData, keyDesc, err := o.newKeyData(req, result.cert, result.key)
	if err != nil {
		return s.p.fail(&failure{code: exitProtocol, Title: "The response cannot be used", Message: err.Error()}, err)
	}
	if o.op != estServerKeyGen && !bytes.Equal(result.cert.RawSubjectPublicKeyInfo, req.csr.RawSubjectPublicKeyInfo) {
		err := errors.New("the certificate certifies another key than the request")
		return s.p.fail(&failure{code: exitProtocol, Title: "The response cannot be used", Message: err.Error()}, err)
	}
	saved, err := o.save(result.cert, keyData)
	if err != nil {
		return fmt.Errorf("the certificate was issued but could not be saved: %w", err)
	}
	title := map[string]string{
		estEnroll:       "Certificate issued",
		estReenroll:     "Certificate renewed",
		estServerKeyGen: "Certificate and key issued",
	}[o.op]
	fields := append(describeCertificate(result.cert), ui.Field{Name: fieldSaved, Value: strings.Join(saved, ", ")})
	p.result(title, fields, &estEnrollJSON{Certificate: certificateResult(result.cert), Key: keyDesc, Saved: saved})
	return nil
}

// prepareRequest builds the request. renewed is the certificate est reenroll renews, whose subject
// and subjectAltName the request repeats as RFC 7030 section 4.2.2 requires. The password of an
// encrypted --new-key may be prompted for on stdin.
func (o *estEnrollOptions) prepareRequest(renewed *x509.Certificate, stdin io.Reader, prompt io.Writer) (*estRequest, error) {
	req := &estRequest{}
	switch {
	case o.csr != "":
		der, err := pemfile.ReadCSR(o.csr)
		if err != nil {
			return nil, err
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.csr, err)
		}
		req.csr = csr
		return req, nil
	case o.newKey != "":
		key, err := o.keyPassword.loadSigner(o.newKey, stdin, prompt)
		if err != nil {
			return nil, err
		}
		req.key = key
	default:
		key, err := keys.GenerateSigner(o.keyType)
		if err != nil {
			return nil, err
		}
		req.key = key
	}

	tmpl := &x509.CertificateRequest{}
	if renewed != nil {
		tmpl.RawSubject = renewed.RawSubject
		for _, ext := range renewed.Extensions {
			if ext.Id.Equal(oidSubjectAltName) {
				tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			}
		}
	} else {
		if o.subject != "" {
			name, err := dn.ParseName(o.subject)
			if err != nil {
				return nil, fmt.Errorf("--subject: %w", err)
			}
			tmpl.Subject = name
		}
		exts, err := sanExtensions(o.sans, o.subject != "")
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = exts
	}
	der, err := compositex509.CreateCertificateRequest(rand.Reader, tmpl, req.key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	if req.csr, err = x509.ParseCertificateRequest(der); err != nil {
		return nil, err
	}
	return req, nil
}

// oidSubjectAltName identifies the subjectAltName extension.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// newKeyData returns the encoded form and description of the key to save with cert. It is the generated
// key or, for serverkeygen, the key from the server. It returns no key for --new-key and --csr.
func (o *estEnrollOptions) newKeyData(req *estRequest, cert *x509.Certificate, serverKey []byte) ([]byte, string, error) {
	if o.op != estServerKeyGen {
		if o.keyOut == "" {
			return nil, "", nil
		}
		data, err := o.format.key(req.key)
		return data, keys.Describe(req.key.Public()), err
	}
	if !isPKCS8(serverKey) {
		return nil, "", errors.New("the server encrypted the private key (RFC 7030 section 4.4.2), " +
			"and certrally cannot decrypt it")
	}
	desc := pkcs8Algorithm(serverKey)
	if parsed, err := compositex509.ParsePKCS8PrivateKey(serverKey); err == nil {
		if signer, ok := parsed.(crypto.Signer); ok {
			pub, err := keys.CertificateKey(cert)
			matcher, comparable := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
			if err == nil && comparable && !matcher.Equal(pub) {
				return nil, "", errors.New("the private key from the server does not belong to the certificate")
			}
			desc = keys.Describe(signer.Public())
		}
	}
	return o.format.block("PRIVATE KEY", serverKey), desc, nil
}

// isPKCS8 reports whether der is a PrivateKeyInfo or OneAsymmetricKey, which starts with a version
// number, rather than a CMS message, which starts with a content type.
func isPKCS8(der []byte) bool {
	input := cryptobyte.String(der)
	var seq cryptobyte.String
	return input.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.PeekASN1Tag(cbasn1.INTEGER)
}

// pkcs8Algorithm names the algorithm of a PKCS#8 key, for keys certrally cannot parse such as
// ML-KEM.
func pkcs8Algorithm(der []byte) string {
	var info struct {
		Version   int
		Algorithm pkix.AlgorithmIdentifier
		Key       []byte
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return ""
	}
	if name, ok := keyAlgorithmNames[info.Algorithm.Algorithm.String()]; ok {
		return name
	}
	return trace.AlgorithmName(info.Algorithm.Algorithm)
}

// keyAlgorithmNames maps the OIDs of keys that only a server generates to display names.
var keyAlgorithmNames = map[string]string{
	"2.16.840.1.101.3.4.4.1": "ML-KEM-512",
	"2.16.840.1.101.3.4.4.2": "ML-KEM-768",
	"2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

// save writes the key, then the certificate. It returns the paths written. The key comes first so
// that a certificate file never exists without its key.
func (o *estEnrollOptions) save(cert *x509.Certificate, keyData []byte) ([]string, error) {
	saved := []string{}
	if keyData != nil {
		if err := pemfile.Write(o.keyOut, keyData, 0o600, o.force); err != nil {
			return saved, err
		}
		saved = append(saved, o.keyOut)
	}
	if err := pemfile.Write(o.certOut, o.format.certificate(cert), 0o644, o.force); err != nil {
		return saved, err
	}
	return append(saved, o.certOut), nil
}

// warnTLSUnique warns when --tls-unique had no effect because a connection used TLS 1.3, which has
// no tls-unique value.
func (s *estSession) warnTLSUnique() {
	for _, ev := range s.recorder.Events() {
		if ev.Kind == trace.Connect && ev.TLS.Version != "TLS 1.2" {
			s.p.warn("The connection used " + ev.TLS.Version + ", which has no tls-unique value, " +
				"so the request is not bound to the TLS session.")
			return
		}
	}
}
