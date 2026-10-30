package cli

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pkcs7"
	scep "github.com/misiektoja/go-pki-scep"
	"github.com/misiektoja/go-pki-scep/scepclient"
	"github.com/misiektoja/go-pki-scep/x509util"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// scepHashChoice is a --hash value and the digest it selects.
type scepHashChoice struct {
	name, display string
	hash          crypto.Hash
}

// scepHashes are the --hash values, the digests a pkiMessage signature can use. A value is the
// lowercase digest name without hyphens, such as sha256 for SHA-256.
var scepHashes = func() []scepHashChoice {
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA1, crypto.MD5}
	choices := make([]scepHashChoice, 0, len(hashes))
	for _, h := range hashes {
		display := h.String()
		choices = append(choices, scepHashChoice{
			name:    strings.ToLower(strings.ReplaceAll(display, "-", "")),
			display: display,
			hash:    h,
		})
	}
	return choices
}()

// scepHashNames returns the --hash values.
func scepHashNames() []string {
	names := make([]string, len(scepHashes))
	for i, h := range scepHashes {
		names[i] = h.name
	}
	return names
}

// scepCiphers are the --cipher values, the content ciphers of a pkiEnvelope.
var scepCiphers = []struct {
	name, display string
	alg           pkcs7.ContentEncryptionAlgorithm
}{
	{"aes128", "AES-128-CBC", pkcs7.AES128CBC},
	{"aes192", "AES-192-CBC", pkcs7.AES192CBC},
	{"aes256", "AES-256-CBC", pkcs7.AES256CBC},
	{"des3", "DES-EDE3-CBC", pkcs7.DESEDE3CBC},
	{"des", "DES-CBC", pkcs7.DESCBC},
}

// scepHash returns the digest of a --hash value, or zero for "" to let the server capabilities
// choose.
func scepHash(name string) (crypto.Hash, error) {
	if name == "" {
		return 0, nil
	}
	for _, h := range scepHashes {
		if h.name == name || h.display == name {
			return h.hash, nil
		}
	}
	return 0, fmt.Errorf("invalid --hash %q, want sha256, sha384, sha512, sha1 or md5", name)
}

// scepCipher returns the content cipher of a --cipher value, or zero for "" to let the server
// capabilities choose.
func scepCipher(name string) (pkcs7.ContentEncryptionAlgorithm, error) {
	if name == "" {
		return 0, nil
	}
	for _, c := range scepCiphers {
		if c.name == name || c.display == name {
			return c.alg, nil
		}
	}
	return 0, fmt.Errorf("invalid --cipher %q, want aes128, aes192, aes256, des3 or des", name)
}

// The SCEP commands that issue a certificate.
const (
	scepEnroll = "enroll"
	scepRenew  = "renew"
)

// defaultSCEPKeyType is the key type scep enroll generates. SCEP requests are signed and their
// answers decrypted with an RSA key, so RSA is what servers expect.
const defaultSCEPKeyType = "rsa-2048"

// scepEnrollOptions holds the command line of scep enroll and scep renew.
type scepEnrollOptions struct {
	scepConnection
	scepTrust
	outputOptions
	keyPassword
	// op is scepEnroll or scepRenew.
	op            string
	challenge     secret.Value
	challengeFile string
	subject       string
	sans          []string
	keyUsage      []string
	extKeyUsage   []string
	keyType       string
	newKey        string
	csr           string
	// certFile and keyFile are the certificate scep renew renews and its key, which signs the
	// request.
	certFile string
	keyFile  string
	// pkcsReq makes scep renew send a PKCSReq instead of a RenewalReq, as servers that follow the
	// drafts before RFC 8894 expect.
	pkcsReq  bool
	certOut  string
	keyOut   string
	chainOut string
	state    string
	force    bool
	format   outFormat
	hash     string
	cipher   string
	// pollLater stops at the first PENDING answer and leaves the state for scep poll.
	pollLater    bool
	pollInterval time.Duration
}

// scepEnrollTimeoutHelp describes --timeout of the commands that issue a certificate.
const scepEnrollTimeoutHelp = "limit for the whole exchange, including the polls while the CA answers PENDING"

// newSCEPEnrollCommand returns scep enroll.
func newSCEPEnrollCommand() *cobra.Command {
	o := &scepEnrollOptions{op: scepEnroll}
	cmd := &cobra.Command{
		Use:   enrollUse,
		Short: "Request a certificate from a SCEP server",
		Long: "Request a certificate with a PKCSReq (RFC 8894 section 3.3.1) and save it.\n\n" +
			"A new key is generated unless --new-key or --csr supplies one. The challenge password goes in the " +
			"request. certrally signs the request with a certificate it makes for the request key, or for a " +
			"temporary RSA key when the request key is not RSA. The transaction ID is the SHA-1 hash of the " +
			"public key in uppercase hex.\n\n" +
			"When the CA answers PENDING, certrally polls with CertPoll every --poll-interval until it decides, " +
			"within --timeout. A request still pending at the end is saved in the --state file, which " +
			"certrally scep poll continues. --poll-later stops at the first PENDING answer.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep enroll --server http://scep.example.com/scep --ca 'Issuing CA' \\\n" +
			"    --challenge-file challenge.txt --subject CN=device-42 --cert-out device.pem --key-out device.key",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runSCEPEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addCommonFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.subject, flagSubject, "", "subject name, such as CN=device-42,O=Example")
	f.StringArrayVar(&o.sans, flagSAN, nil, "subject alternative name: dns:, ip:, email: or uri: value (repeatable)")
	f.StringArrayVar(&o.keyUsage, "key-usage", nil,
		"key usage to request, such as digitalSignature or keyEncipherment (repeatable, or comma-separated)")
	f.StringArrayVar(&o.extKeyUsage, "ext-key-usage", nil,
		"extended key usage to request, such as clientAuth, serverAuth or a dotted OID (repeatable, or comma-separated)")
	for _, name := range []string{flagSubject, flagSAN} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// newSCEPRenewCommand returns scep renew.
func newSCEPRenewCommand() *cobra.Command {
	o := &scepEnrollOptions{op: scepRenew}
	cmd := &cobra.Command{
		Use:   "renew --server URL --cert FILE --key FILE --cert-out FILE [flags]",
		Short: "Renew a certificate with a SCEP server",
		Long: "Renew the certificate in --cert with a RenewalReq (RFC 8894 section 3.3.1) and save the new one. The " +
			"request repeats the subject and subjectAltName of that certificate and is signed with it and --key, " +
			"which must be RSA. A new key is generated unless --new-key or --csr supplies one. Pass the current key " +
			"with --new-key to keep it. The server must list Renewal in its capabilities.\n\n" +
			"With --pkcsreq certrally sends a PKCSReq signed the same way instead, which servers that follow the " +
			"drafts before RFC 8894 expect for a renewal. They need not list Renewal.\n\n" +
			"PENDING answers are polled as in certrally scep enroll.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep renew --server http://scep.example.com/scep --ca 'Issuing CA' \\\n" +
			"    --cert device.pem --key device.key --cert-out device-new.pem --key-out device-new.key",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runSCEPEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.addCommonFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.certFile, "cert", "", "the certificate to renew, which signs the request")
	f.StringVar(&o.keyFile, "key", "", "the RSA private key of --cert")
	f.BoolVar(&o.pkcsReq, "pkcsreq", false, "send a PKCSReq signed with --cert instead of a RenewalReq")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

// addCommonFlags registers the flags that scep enroll and scep renew share.
func (o *scepEnrollOptions) addCommonFlags(cmd *cobra.Command) {
	o.scepConnection.addFlags(cmd, 5*time.Minute, scepEnrollTimeoutHelp, false)
	o.addDecryptFlags(cmd)
	o.scepTrust.addFlags(cmd)
	o.outputOptions.addFlags(cmd)
	o.keyPassword.addFlags(cmd)
	f := cmd.Flags()
	f.Var(&o.challenge, "challenge",
		"challenge password that authorizes the request, which other users of this machine can see in the process list")
	f.StringVar(&o.challengeFile, "challenge-file", "", "read the challenge password from a file, or - for standard input")
	f.StringVar(&o.keyType, "key-type", defaultSCEPKeyType,
		"type of the generated key: rsa-2048, rsa-3072, rsa-4096, ecdsa-p256, ecdsa-p384 or ecdsa-p521")
	f.StringVar(&o.newKey, "new-key", "", "certify the private key in this file instead of generating one")
	f.StringVar(&o.csr, "csr", "", "send the PKCS#10 request in this file")
	f.StringVar(&o.certOut, "cert-out", "", "write the issued certificate to this file")
	f.StringVar(&o.keyOut, "key-out", "", "write the new private key to this file")
	f.StringVar(&o.chainOut, "chain-out", "", "write the other certificates of the answer, such as the CA, to this file")
	f.StringVar(&o.state, "state", "",
		"keep a pending request in this file for certrally scep poll, by default --cert-out.state")
	f.BoolVar(&o.force, "force", false, "replace existing output files")
	o.format.addFlags(cmd, formatPEM, outFormatHelp)
	f.StringVar(&o.hash, "hash", "", scepEnrollHashHelp)
	f.StringVar(&o.cipher, "cipher", "", "content cipher of the request: aes128, aes192, aes256, des3 or des, by default "+
		"aes128 unless the server lists only DES3")
	f.BoolVar(&o.pollLater, "poll-later", false, "stop at the first PENDING answer and keep the request in --state")
	f.DurationVar(&o.pollInterval, "poll-interval", 30*time.Second, "wait between polls while the CA answers PENDING")
	cmd.MarkFlagsMutuallyExclusive("key-type", "new-key", "csr")
	cmd.MarkFlagsMutuallyExclusive("challenge", "challenge-file")
	_ = cmd.MarkFlagRequired("cert-out")
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(scepKeyTypes()))
	_ = cmd.RegisterFlagCompletionFunc("hash", fixedCompletion(scepHashNames()))
	_ = cmd.RegisterFlagCompletionFunc("cipher", fixedCompletion([]string{"aes128", "aes192", "aes256", "des3", "des"}))
	for _, name := range []string{"challenge", "poll-interval"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// scepKeyTypes lists the key types scep enroll generates: RSA and ECDSA.
func scepKeyTypes() []string {
	var names []string
	for _, name := range keys.SigningTypeNames() {
		if strings.HasPrefix(name, "rsa-") || strings.HasPrefix(name, "ecdsa-") {
			names = append(names, name)
		}
	}
	return names
}

// validate checks flag combinations that cobra cannot express.
func (o *scepEnrollOptions) validate() error {
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
	switch {
	case o.csr != "" && (o.subject != "" || len(o.sans) > 0 || len(o.keyUsage) > 0 || len(o.extKeyUsage) > 0):
		return errors.New("--subject, --san, --key-usage and --ext-key-usage cannot change a request given with --csr")
	case o.csr != "" && (o.challenge.Bytes() != nil || o.challengeFile != ""):
		return errors.New("a challenge password cannot be added to a request given with --csr")
	case o.op == scepEnroll && o.csr == "" && o.subject == "" && len(o.sans) == 0:
		return errors.New("--subject or --san is required")
	case !slices.Contains(scepKeyTypes(), o.keyType):
		return fmt.Errorf("invalid --key-type %q, want %s", o.keyType, strings.Join(scepKeyTypes(), ", "))
	case o.pollInterval <= 0:
		return errors.New("--poll-interval must be positive")
	}
	generated := o.csr == "" && o.newKey == ""
	switch {
	case generated && o.keyOut == "":
		return errors.New("--key-out is required to save the new key")
	case !generated && o.keyOut != "":
		return errors.New("--key-out is only used with a new key")
	}
	if err := o.format.validate(); err != nil {
		return err
	}
	if err := o.checkStdin("--challenge-file", o.challengeFile); err != nil {
		return err
	}
	return o.checkCapture(o.certOut, o.keyOut, o.chainOut, o.statePath())
}

// statePath returns the --state file, which defaults to the --cert-out file followed by .state.
func (o *scepEnrollOptions) statePath() string {
	if o.state != "" {
		return o.state
	}
	return o.certOut + ".state"
}

// scepRequest is an enrollment ready to send.
type scepRequest struct {
	messageType scep.MessageType
	// renewal is set for scep renew, which can also send a PKCSReq.
	renewal bool
	csr     *x509.CertificateRequest
	// key is the key the request certifies. It is nil for --csr. generated is set when certrally
	// generated it, so that it goes to --key-out.
	key       crypto.Signer
	generated bool
	// signerCert and signerKey sign the request and decrypt the answer. signerKeyFile is the file
	// that holds signerKey, or "" for a temporary key that only the state file keeps.
	signerCert    *x509.Certificate
	signerKey     crypto.Signer
	signerKeyFile string
	transactionID scep.TransactionID
	digest        crypto.Hash
	cipher        pkcs7.ContentEncryptionAlgorithm
}

// enrollRequest returns the request for go-pki-scep.
func (r *scepRequest) enrollRequest() scepclient.EnrollRequest {
	return scepclient.EnrollRequest{
		MessageType:       r.messageType,
		CSR:               r.csr,
		SignerCertificate: r.signerCert,
		SignerKey:         r.signerKey,
		TransactionID:     r.transactionID,
		Digest:            r.digest,
		Encryption:        pkcs7.EncryptOptions{ContentEncryption: r.cipher},
	}
}

// runSCEPEnroll performs scep enroll or scep renew.
func runSCEPEnroll(ctx context.Context, o *scepEnrollOptions, p *printer, stdin io.Reader) error {
	if err := o.validate(); err != nil {
		return err
	}
	if err := p.confirmOutputs(&o.force, o.certOut, o.keyOut, o.chainOut, o.statePath()); err != nil {
		return err
	}
	pinned, err := o.loadPinned()
	if err != nil {
		return err
	}
	fp, _ := o.fingerprintBytes()
	challenge, err := readChallenge(o.challenge, o.challengeFile, stdin)
	if err != nil {
		return err
	}
	req, err := o.prepareRequest(challenge, stdin, p.stderr)
	if err != nil {
		return err
	}
	s, err := o.scepConnection.open(p)
	if err != nil {
		return err
	}
	w := &scepWait{s: s, interval: o.pollInterval, pollLater: o.pollLater, onPending: func(res *scepclient.Result) error {
		return o.savePending(s, req, res)
	}}
	err = s.run(ctx, func(ctx context.Context) error {
		caps, err := s.client.GetCACaps(ctx)
		if httpErr, ok := errors.AsType[*scepclient.HTTPError](err); ok && httpErr.StatusCode != 503 {
			s.warnAfterLadder(fmt.Sprintf("The server answered GetCACaps with HTTP %d, so certrally assumes it "+
				"lists no capabilities.", httpErr.StatusCode))
		} else if err != nil {
			return err
		}
		if req.messageType == scep.RenewalReq && !caps.Has("Renewal") {
			s.warnAfterLadder("The server does not list Renewal in its capabilities, so it may refuse the RenewalReq.")
		}
		ca, err := s.caCertificates(ctx, pinned, fp)
		if err != nil {
			return err
		}
		return w.enroll(ctx, ca, req)
	})
	if _, rejected := errors.AsType[*scepFailureError](err); rejected && w.kept {
		if rerr := removeSCEPState(o.statePath()); rerr != nil {
			p.warn("The rejected request is still in " + o.statePath() + ": " + rerr.Error())
		}
	}
	if err != nil {
		return err
	}
	return o.finish(s, req, w)
}

// prepareRequest builds the request and the certificate that signs it. The password of an
// encrypted --new-key or --key may be prompted for on stdin.
func (o *scepEnrollOptions) prepareRequest(challenge string, stdin io.Reader, prompt io.Writer) (*scepRequest, error) {
	req := &scepRequest{messageType: scep.PKCSReq}
	var err error
	if req.digest, err = scepHash(o.hash); err != nil {
		return nil, err
	}
	if req.cipher, err = scepCipher(o.cipher); err != nil {
		return nil, err
	}
	var renewed *x509.Certificate
	if o.op == scepRenew {
		req.renewal = true
		if !o.pkcsReq {
			req.messageType = scep.RenewalReq
		}
		chain, err := pemfile.ReadCertificates(o.certFile)
		if err != nil {
			return nil, err
		}
		renewed = chain[0]
		signer, err := o.keyPassword.loadSigner(o.keyFile, stdin, prompt)
		if err != nil {
			return nil, err
		}
		if _, ok := signer.(*rsa.PrivateKey); !ok {
			return nil, errors.New("--key must be an RSA key, because SCEP answers are encrypted for the key that signs")
		}
		if !publicKeyEqual(signer.Public(), renewed.PublicKey) {
			return nil, errors.New("--key is not the key of the certificate in --cert")
		}
		req.signerCert, req.signerKey = renewed, signer
		if req.signerKeyFile, err = filepath.Abs(o.keyFile); err != nil {
			return nil, err
		}
	}

	switch {
	case o.csr != "":
		der, err := pemfile.ReadCSR(o.csr)
		if err != nil {
			return nil, err
		}
		if req.csr, err = x509.ParseCertificateRequest(der); err != nil {
			return nil, fmt.Errorf("%s: %w", o.csr, err)
		}
	case o.newKey != "":
		if req.key, err = o.keyPassword.loadSigner(o.newKey, stdin, prompt); err != nil {
			return nil, err
		}
	default:
		if req.key, err = keys.GenerateSigner(o.keyType); err != nil {
			return nil, err
		}
		req.generated = true
	}
	if req.key != nil {
		if req.csr, err = o.createCSR(req.key, renewed, challenge, req.digest); err != nil {
			return nil, err
		}
	}
	id, err := scep.CSRTransactionID(req.csr)
	if err != nil {
		return nil, err
	}
	// Most SCEP clients send the hex digest in upper case.
	req.transactionID = scep.TransactionID(strings.ToUpper(string(id)))
	if req.signerCert != nil {
		return req, nil
	}

	// RFC 8894 section 2.3 has the requester sign with a self-signed certificate for the request
	// key. Answers are encrypted for that key, so a key that is not RSA needs a temporary RSA key.
	signer, ok := req.key.(*rsa.PrivateKey)
	switch {
	case ok && req.generated:
		if req.signerKeyFile, err = filepath.Abs(o.keyOut); err != nil {
			return nil, err
		}
	case ok:
		if req.signerKeyFile, err = filepath.Abs(o.newKey); err != nil {
			return nil, err
		}
	default:
		if signer, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return nil, err
		}
	}
	req.signerKey = signer
	if req.signerCert, err = selfSignedSigner(req.csr.RawSubject, signer); err != nil {
		return nil, err
	}
	return req, nil
}

// createCSR returns the PKCS#10 request for key, signed with the --hash digest when it names one.
// crypto/x509 does not sign with MD5, so MD5 keeps its default. renewed is the certificate scep renew
// renews, whose subject and subjectAltName the request repeats.
func (o *scepEnrollOptions) createCSR(key crypto.Signer, renewed *x509.Certificate, challenge string, digest crypto.Hash) (*x509.CertificateRequest, error) {
	tmpl := &x509util.CertificateRequest{ChallengePassword: challenge}
	tmpl.SignatureAlgorithm = csrSignatureAlgorithm(key, digest)
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
		usageExts, err := o.usageExtensions()
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = slices.Concat(exts, usageExts)
	}
	der, err := x509util.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	return x509.ParseCertificateRequest(der)
}

// usageExtensions returns the keyUsage and extendedKeyUsage extensions of --key-usage and
// --ext-key-usage.
func (o *scepEnrollOptions) usageExtensions() ([]pkix.Extension, error) {
	var exts []pkix.Extension
	if names, err := splitNames("key-usage", o.keyUsage); err != nil {
		return nil, err
	} else if len(names) > 0 {
		ext, err := keyUsageExtension(names)
		if err != nil {
			return nil, err
		}
		exts = append(exts, ext)
	}
	if names, err := splitNames("ext-key-usage", o.extKeyUsage); err != nil {
		return nil, err
	} else if len(names) > 0 {
		ext, err := extKeyUsageExtension(names)
		if err != nil {
			return nil, err
		}
		exts = append(exts, ext)
	}
	return exts, nil
}

// publicKeyEqual reports whether two public keys are equal.
func publicKeyEqual(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// selfSignedSigner returns the self-signed certificate that signs a request for the subject. Its
// key usage lets the CA encrypt the answer for it (RFC 8894 section 2.3).
func selfSignedSigner(subject []byte, key *rsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)),
		RawSubject:   subject,
		RawIssuer:    subject,
		NotBefore:    now.Add(-time.Hour),
		// A CA may take weeks to approve a request, and every poll is signed with this certificate.
		NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create the signer certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// scepWait sends an enrollment or a poll and polls while the CA answers PENDING.
type scepWait struct {
	s         *scepSession
	interval  time.Duration
	pollLater bool
	// onPending is called with the first PENDING answer, before any wait, to keep the request.
	onPending func(*scepclient.Result) error
	// result is the last answer. polls counts the CertPoll requests sent.
	result *scepclient.Result
	polls  int
	// timedOut is set when --timeout ended the polling while the CA still answered PENDING.
	timedOut bool
	// kept is set once onPending kept the request.
	kept bool
}

// enroll sends req and polls as long as the answer is PENDING.
func (w *scepWait) enroll(ctx context.Context, ca *scepclient.CACertificates, req *scepRequest) error {
	res, err := w.s.client.Enroll(ctx, ca, req.enrollRequest())
	if err != nil {
		return err
	}
	return w.wait(ctx, ca, req, res)
}

// poll sends CertPoll for req and keeps polling as long as the answer is PENDING, unless once is set.
func (w *scepWait) poll(ctx context.Context, ca *scepclient.CACertificates, req *scepRequest) error {
	res, err := w.s.client.Poll(ctx, ca, req.enrollRequest())
	if err != nil {
		return err
	}
	w.polls++
	return w.wait(ctx, ca, req, res)
}

// wait polls while res is PENDING. It returns the error of a FAILURE answer.
func (w *scepWait) wait(ctx context.Context, ca *scepclient.CACertificates, req *scepRequest, res *scepclient.Result) error {
	for {
		w.result = res
		switch res.Status {
		case scep.SUCCESS:
			return nil
		case scep.FAILURE:
			return &scepFailureError{failInfo: trace.SCEPFailInfoName(string(res.FailInfo))}
		case scep.PENDING:
		}
		if !w.kept {
			if err := w.onPending(res); err != nil {
				return err
			}
			w.kept = true
		}
		if w.pollLater {
			return nil
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < w.interval {
			w.timedOut = true
			return nil
		}
		if w.s.ladder != nil {
			w.s.ladder.Note(fmt.Sprintf("pending, polling again in %s", w.interval))
		}
		select {
		case <-time.After(w.interval):
		case <-ctx.Done():
			w.timedOut = true
			return nil
		}
		next, err := w.s.client.Poll(ctx, ca, req.enrollRequest())
		if errors.Is(err, context.DeadlineExceeded) {
			w.timedOut = true
			return nil
		}
		if err != nil {
			return err
		}
		w.polls++
		res = next
	}
}

// scepStateVersion is the version of the --state file format.
const scepStateVersion = 1

// scepState is the --state file of a request the CA answered PENDING: what CertPoll needs to
// continue it. It can hold a private key, so it is written with mode 0600. Paths are absolute, so
// that scep poll can run from another directory.
type scepState struct {
	Version       int    `json:"version"`
	Server        string `json:"server"`
	CAName        string `json:"caName,omitempty"`
	MessageType   string `json:"messageType"`
	TransactionID string `json:"transactionId"`
	// Digest and Cipher are the --hash and --cipher values the request used.
	Digest string `json:"digest"`
	Cipher string `json:"cipher"`
	// AllowDES is --allow-des, which the answer to CertPoll needs as much as the first answer.
	AllowDES bool `json:"allowDES,omitempty"`
	// CACertificates, CSR and SignerCertificate are PEM.
	CACertificates    string `json:"caCertificates"`
	CSR               string `json:"csr"`
	SignerCertificate string `json:"signerCertificate"`
	// Renewal is set for scep renew, which can also send a PKCSReq.
	Renewal bool `json:"renewal,omitempty"`
	// SignerKey is the PEM of a temporary RSA key that signs the requests. SignerKeyFile names the
	// file of the signer key instead when the key exists elsewhere.
	SignerKey     string    `json:"signerKey,omitempty"`
	SignerKeyFile string    `json:"signerKeyFile,omitempty"`
	CertOut       string    `json:"certOut"`
	ChainOut      string    `json:"chainOut,omitempty"`
	KeyOut        string    `json:"keyOut,omitempty"`
	OutFormat     string    `json:"outFormat,omitempty"`
	Started       time.Time `json:"started"`
}

// savePending saves the generated key and the state of a request the CA answered PENDING, so that
// scep poll can continue it even if this run ends early.
func (o *scepEnrollOptions) savePending(s *scepSession, req *scepRequest, res *scepclient.Result) error {
	if req.generated {
		data, err := o.format.key(req.key)
		if err != nil {
			return err
		}
		if err := pemfile.Write(o.keyOut, data, 0o600, o.force); err != nil {
			return fmt.Errorf("the request is pending, but the key could not be saved: %w", err)
		}
	}
	state, err := newSCEPState(s, req, res, o.certOut, o.chainOut, o.keyOut, o.format.name)
	if err != nil {
		return err
	}
	return writeSCEPState(o.statePath(), state, o.force)
}

// newSCEPState returns the state of a pending request.
func newSCEPState(s *scepSession, req *scepRequest, res *scepclient.Result, certOut, chainOut, keyOut, format string) (*scepState, error) {
	state := &scepState{
		Version:           scepStateVersion,
		Server:            s.conn.server,
		CAName:            s.conn.caName,
		MessageType:       scepMessageTypeName(req.messageType),
		Renewal:           req.renewal,
		TransactionID:     string(res.TransactionID),
		Digest:            scepRequestDigest(s, req.digest),
		Cipher:            scepRequestCipher(s, req.cipher),
		AllowDES:          s.conn.allowDES,
		CACertificates:    string(pemfile.EncodeCertificates(s.ca.All)),
		CSR:               pemString("CERTIFICATE REQUEST", req.csr.Raw),
		SignerCertificate: pemString("CERTIFICATE", req.signerCert.Raw),
		OutFormat:         format,
		Started:           time.Now().UTC(),
	}
	for _, path := range []struct {
		dst *string
		src string
	}{{&state.CertOut, certOut}, {&state.ChainOut, chainOut}, {&state.KeyOut, keyOut}} {
		if path.src == "" {
			continue
		}
		abs, err := filepath.Abs(path.src)
		if err != nil {
			return nil, err
		}
		*path.dst = abs
	}
	if req.signerKeyFile != "" {
		state.SignerKeyFile = req.signerKeyFile
	} else {
		data, err := keys.MarshalPEM(req.signerKey)
		if err != nil {
			return nil, err
		}
		state.SignerKey = string(data)
	}
	return state, nil
}

// scepMessageTypeName names a request message type, such as "PKCSReq".
func scepMessageTypeName(t scep.MessageType) string {
	name, _, _ := strings.Cut(t.String(), " ")
	return name
}

// scepRequestDigest returns the --hash value of the digest the last request used. A zero digest is
// read from the request the client sent.
func scepRequestDigest(s *scepSession, digest crypto.Hash) string {
	display := ""
	for _, h := range scepHashes {
		if h.hash == digest {
			return h.name
		}
	}
	if req := s.lastSCEPRequest(); req != nil {
		display = req.Digest
	}
	for _, h := range scepHashes {
		if h.display == display {
			return h.name
		}
	}
	return ""
}

// scepRequestCipher returns the --cipher value of the cipher the last request used. A zero cipher
// is read from the request the client sent.
func scepRequestCipher(s *scepSession, alg pkcs7.ContentEncryptionAlgorithm) string {
	display := ""
	for _, c := range scepCiphers {
		if c.alg == alg {
			return c.name
		}
	}
	if req := s.lastSCEPRequest(); req != nil {
		display = req.Cipher
	}
	for _, c := range scepCiphers {
		if c.display == display {
			return c.name
		}
	}
	return ""
}

// lastSCEPRequest returns the summary of the last pkiMessage sent, or nil when none was.
func (s *scepSession) lastSCEPRequest() *trace.SCEPSummary {
	for _, ev := range slices.Backward(s.recorder.Events()) {
		if ev.Kind == trace.Request && ev.SCEP != nil && ev.SCEP.MessageType != "" {
			return ev.SCEP
		}
	}
	return nil
}

// writeSCEPState writes the state file with mode 0600.
func writeSCEPState(path string, state *scepState, force bool) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := pemfile.Write(path, append(data, '\n'), 0o600, force); err != nil {
		return fmt.Errorf("the request is pending, but --state could not be written: %w", err)
	}
	return nil
}

// removeSCEPState removes the state file of a transaction that ended. A file that does not exist
// is no error.
func removeSCEPState(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// finish reports the outcome of an enrollment. A certificate is saved with its chain and a pending
// request is reported with the command that continues it.
func (o *scepEnrollOptions) finish(s *scepSession, req *scepRequest, w *scepWait) error {
	out := scepOutputs{
		certOut:  o.certOut,
		chainOut: o.chainOut,
		keyOut:   o.keyOut,
		state:    o.statePath(),
		force:    o.force,
		format:   o.format,
	}
	if req.generated {
		out.key = req.key
	}
	title := map[string]string{scepEnroll: titleCertificateIssued, scepRenew: titleCertificateRenewed}[o.op]
	return out.report(s, req, w, title)
}

// scepOutputs are the files an enrollment or a poll writes.
type scepOutputs struct {
	certOut, chainOut, keyOut, state string
	force                            bool
	format                           outFormat
	// key is the generated key to save with the certificate. It is nil when the key exists already
	// or was saved with the pending state.
	key crypto.Signer
}

// report saves the certificate of a SUCCESS answer or reports a request still pending.
func (out *scepOutputs) report(s *scepSession, req *scepRequest, w *scepWait, title string) error {
	res := w.result
	result := &scepEnrollJSON{
		Status:        string(trace.SCEPPending),
		MessageType:   scepMessageTypeName(req.messageType),
		TransactionID: string(req.transactionID),
		Digest:        scepRequestDigest(s, req.digest),
		Cipher:        scepRequestCipher(s, req.cipher),
		Chain:         []*certificateJSON{},
		Polls:         w.polls,
		Saved:         []string{},
	}
	if res.Status == scep.PENDING {
		return out.reportPending(s, w, result)
	}
	result.Status = trace.SCEPSuccess
	chain := slices.DeleteFunc(slices.Clone(res.Certificates), func(c *x509.Certificate) bool {
		return c == res.Certificate
	})
	saved, err := out.save(res.Certificate, chain, w.kept)
	if err != nil {
		return fmt.Errorf("the certificate was issued but could not be saved: %w", err)
	}
	if err := removeSCEPState(out.state); err != nil {
		s.p.warn("The finished request is still in " + out.state + ": " + err.Error())
	}
	result.Certificate = certificateResult(res.Certificate)
	result.Chain = certificatesResult(chain)
	result.Saved = saved
	if out.key != nil {
		result.Key = keys.Describe(out.key.Public())
	}
	fields := append(describeCertificate(res.Certificate),
		ui.Field{Name: fieldTransactionID, Value: ui.Sanitize(result.TransactionID)},
		ui.Field{Name: fieldRequest, Value: scepRequestText(result)},
		ui.Field{Name: fieldSaved, Value: strings.Join(saved, ", ")},
	)
	s.p.result(title, fields, result)
	return nil
}

// scepRequestText describes the message type and algorithms of a request.
func scepRequestText(r *scepEnrollJSON) string {
	text := r.MessageType
	if d := scepHashDisplay(r.Digest); d != "" {
		text += ", signed with " + d
	}
	if c := scepCipherDisplay(r.Cipher); c != "" {
		text += ", encrypted with " + c
	}
	if r.Polls > 0 {
		text += ", " + count(r.Polls, "poll", "polls")
	}
	return text
}

// scepHashDisplay returns the display name of a --hash value.
func scepHashDisplay(name string) string {
	for _, h := range scepHashes {
		if h.name == name {
			return h.display
		}
	}
	return ""
}

// scepCipherDisplay returns the display name of a --cipher value.
func scepCipherDisplay(name string) string {
	for _, c := range scepCiphers {
		if c.name == name {
			return c.display
		}
	}
	return ""
}

// reportPending reports a request the CA still answers PENDING. After --poll-later it is a result.
// When --timeout ended the polling it is a failure.
func (out *scepOutputs) reportPending(s *scepSession, w *scepWait, result *scepEnrollJSON) error {
	result.State = out.state
	if out.keyOut != "" && out.key != nil {
		result.Saved = append(result.Saved, out.keyOut)
	}
	result.Saved = append(result.Saved, out.state)
	note := "Collect the certificate with: " + programName + " " + scepCommand + " poll --state " + shellQuote(out.state)
	if !w.timedOut {
		s.p.result("Request pending at the CA", []ui.Field{
			{Name: fieldStatus, Value: trace.SCEPPending},
			{Name: fieldTransactionID, Value: ui.Sanitize(result.TransactionID)},
			{Name: fieldRequest, Value: scepRequestText(result)},
			{Name: fieldSaved, Value: strings.Join(result.Saved, ", ")},
			{Name: fieldNote, Value: note},
		}, result)
		return nil
	}
	err := fmt.Errorf("the CA still answers PENDING after %s: %w", s.conn.timeout, context.DeadlineExceeded)
	f := &failure{
		code:    exitTransport,
		Title:   "The CA has not decided yet",
		Message: err.Error(),
		Hint:    fmt.Sprintf("The CA kept the request pending for longer than --timeout %s.", s.conn.timeout),
		Note:    note,
	}
	s.p.doc.Result = result
	return s.p.fail(f, err, withSaved(f.fields(s.recording), result.Saved)...)
}

// save writes the key, then the certificate and the chain. It returns the paths written. The key
// comes first so that a certificate file never exists without its key. keySaved is set when the
// key was saved with the pending state already.
func (out *scepOutputs) save(cert *x509.Certificate, chain []*x509.Certificate, keySaved bool) ([]string, error) {
	saved := []string{}
	if out.key != nil {
		if !keySaved {
			data, err := out.format.key(out.key)
			if err != nil {
				return saved, err
			}
			if err := pemfile.Write(out.keyOut, data, 0o600, out.force); err != nil {
				return saved, err
			}
		}
		saved = append(saved, out.keyOut)
	}
	// A pending request may have written the key and the state, so the outputs are replaced.
	force := out.force || keySaved
	if err := pemfile.Write(out.certOut, out.format.certificate(cert), 0o644, force); err != nil {
		return saved, err
	}
	saved = append(saved, out.certOut)
	if out.chainOut != "" {
		data, err := out.format.certificates(chain)
		if err != nil {
			return saved, err
		}
		if err := pemfile.Write(out.chainOut, data, 0o644, force); err != nil {
			return saved, err
		}
		saved = append(saved, out.chainOut)
	}
	return saved, nil
}
