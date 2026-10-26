package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/capture"
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
	reqType string
	subject string
	sans    []string
	// keyUsage and extKeyUsage hold the comma-separated --key-usage and --ext-key-usage values.
	keyUsage     []string
	extKeyUsage  []string
	templateCert string
	keyType      string
	newKey       string
	csr          string
	certOutputs
	certProfile string
	certReqID   int64
	// implicitConfirm asks the CA to skip the certConf round trip.
	implicitConfirm bool
	// pollLater stops at the first answer that says the request waits, for poll to resume.
	pollLater bool
	// pop is the --pop method of a key that cannot sign. Empty selects popEncryptedCert.
	pop string
	// centralKeygen asks the CA to generate the key pair. keyTypeSet records that --key-type was
	// given, so that it names the algorithm to ask for instead of leaving the choice to the CA.
	centralKeygen bool
	keyTypeSet    bool
	interactive   bool
}

// flagCentralKeygen names the flag that asks the CA to generate the key pair.
const flagCentralKeygen = "central-keygen"

// flagPOP names the flag that chooses the indirect proof of possession.
const flagPOP = "pop"

// --pop values: the indirect proofs of possession of RFC 9810 section 5.2.8.3.
const (
	popEncryptedCert = "encrypted-cert"
	popChallenge     = "challenge"
)

// popMethods maps the --pop values to the methods of go-pki-cmp.
var popMethods = map[string]client.IndirectPOP{
	popEncryptedCert: client.EncryptedCertificate,
	popChallenge:     client.ChallengeResponse,
}

// certOutputs names the files that an issued certificate, its new key and the issuing CA
// certificates are written to.
type certOutputs struct {
	certOut  string
	keyOut   string
	chainOut string
	force    bool
	// format is the encoding of the files.
	format outFormat
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
			"A CA that cannot decide at once answers that the request waits, and enroll polls until it " +
			"decides or --timeout ends. With --poll-later enroll stops at that answer instead, saves the new " +
			"key and records the transaction in the --capture file. certrally poll collects the " +
			"certificate later. A run whose polling ends at --timeout records the transaction the same way " +
			"when --capture is given.\n\n" +
			"--key-usage and --ext-key-usage add the keyUsage and extendedKeyUsage extensions to the request. " +
			"--template-cert copies the subject, subjectAltName, keyUsage and extendedKeyUsage of an existing " +
			"certificate. A flag given for a copied part replaces it: --subject, --san, --key-usage or " +
			"--ext-key-usage.\n\n" +
			"An ML-KEM key, from --key-type ml-kem-768 or ml-kem-1024 or --new-key, cannot sign, so it proves " +
			"possession by decryption. With --pop encrypted-cert, the default, the CA encrypts the certificate " +
			"for the key and the certConf proves that enroll could read it. With --pop challenge the CA first " +
			"sends an encrypted challenge that enroll answers. The CA must offer the method.\n\n" +
			"With --central-keygen the CA generates the key pair (RFC 9483 section 4.1.6) and returns the " +
			"private key encrypted for the shared secret or for the --key of a signed request, which must be " +
			"an RSA or ECDSA key. enroll checks that the key belongs to the certificate and saves it to " +
			"--key-out. --key-type names the algorithm to ask for. Without it the CA chooses. An RSA request " +
			"cannot name the key size.\n\n" +
			"With --ra-cert and --ra-key enroll acts as a registration authority (RFC 9483 section 5.2.2.1). " +
			"It wraps every request, including the certConf and pollReq, in a nested message signed with that " +
			"certificate. The request inside keeps its own protection. The CA must accept the authority, " +
			"usually by its cmcRA extended key usage.\n\n" +
			"Run without flags on a terminal, or with --interactive, to be asked for each setting. The " +
			"equivalent command is printed before the request is sent.\n\n" +
			enrollExitStatusHelp,
		Example: "  certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \\\n" +
			"    --secret-file secret.txt --subject CN=device-42 --san device-42.example.com \\\n" +
			"    --cert-out device.pem --key-out device.key\n\n" +
			"  certrally enroll --server https://ca.example.com/.well-known/cmp --type kur \\\n" +
			"    --cert device.pem --key device.key --cert-out device-new.pem --key-out device-new.key",
		Args: cobra.NoArgs,
		// The wizard runs before cobra checks the required flags, because it fills them in.
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return startEnrollWizard(cmd, o)
		},
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			o.keyTypeSet = cmd.Flags().Changed("key-type")
			return runEnroll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.connection.addFlags(cmd, 5*time.Minute, "limit for the whole exchange, including polling")
	o.protection.addFlags(cmd)
	o.protection.addRAFlags(cmd)
	o.outputOptions.addFlags(cmd)

	f := cmd.Flags()
	f.StringVar(&o.reqType, "type", typeIR, "request type: ir, cr, kur or p10cr")
	f.StringVar(&o.subject, flagSubject, "", "subject name, such as CN=device-42,O=Example")
	f.StringArrayVar(&o.sans, flagSAN, nil, "subject alternative name: dns:, ip:, email: or uri: value (repeatable)")
	f.StringArrayVar(&o.keyUsage, flagKeyUsage, nil,
		"key usages to request, comma-separated: digitalSignature, nonRepudiation (or contentCommitment), "+
			"keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly")
	f.StringArrayVar(&o.extKeyUsage, flagExtKeyUsage, nil,
		"extended key usages to request, comma-separated: serverAuth, clientAuth, codeSigning, emailProtection, "+
			"timeStamping, ocspSigning, anyExtendedKeyUsage, cmcRA or a dotted OID")
	f.StringVar(&o.templateCert, flagTemplateCert, "",
		"copy the subject, alternative names and key usages of the certificate in this file (ir, cr or p10cr)")
	f.StringVar(&o.keyType, "key-type", keys.DefaultType,
		"type of the generated key, such as ecdsa-p384, rsa-3072, ml-dsa-65, mldsa65-ecdsa-p256-sha512 or ml-kem-768")
	f.StringVar(&o.pop, flagPOP, "",
		"how a key that cannot sign, such as ML-KEM, proves possession: encrypted-cert (the default) or challenge")
	f.BoolVar(&o.centralKeygen, flagCentralKeygen, false,
		"ask the CA to generate the key pair and save the private key it returns to --key-out")
	f.StringVar(&o.newKey, "new-key", "", "certify the private key in this file instead of generating one")
	f.StringVar(&o.csr, "csr", "", "send the PKCS#10 request in this file (p10cr)")
	f.StringVar(&o.certOut, "cert-out", "", "write the issued certificate to this file")
	f.StringVar(&o.keyOut, "key-out", "", "write the private key that certrally or the CA generates to this file")
	f.StringVar(&o.chainOut, "chain-out", "", "write the issuing CA certificates from the response to this file")
	o.format.addFlags(cmd, formatPEM, outFormatChainHelp)
	f.BoolVar(&o.force, "force", false, "replace existing output files")
	f.StringVar(&o.certProfile, "cert-profile", "", "certificate profile to request")
	f.Int64Var(&o.certReqID, "cert-req-id", 0,
		"request identifier (certReqId) of an ir, cr or kur, which the CA must repeat")
	f.BoolVar(&o.implicitConfirm, "implicit-confirm", false,
		"ask the CA for implicit confirmation, which skips the certConf when granted")
	f.BoolVar(&o.pollLater, "poll-later", false,
		"stop when the CA answers that the request waits and record the transaction in --capture for poll")
	f.BoolVar(&o.interactive, "interactive", false, "ask for the settings that the command line leaves out")

	_ = cmd.MarkFlagRequired("cert-out")
	cmd.MarkFlagsMutuallyExclusive("key-type", "new-key", "csr")
	_ = cmd.RegisterFlagCompletionFunc("type", fixedCompletion(requestTypes))
	_ = cmd.RegisterFlagCompletionFunc("key-type", fixedCompletion(keys.TypeNames()))
	_ = cmd.RegisterFlagCompletionFunc(flagPOP, fixedCompletion([]string{popEncryptedCert, popChallenge}))
	_ = cmd.RegisterFlagCompletionFunc(flagKeyUsage, listCompletion(keyUsageNames))
	_ = cmd.RegisterFlagCompletionFunc(flagExtKeyUsage, listCompletion(keyPurposeNames))
	for _, name := range []string{flagSubject, flagSAN, "cert-profile", "cert-req-id"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// Exit statuses of the commands that talk to a server. Only enroll and poll confirm a certificate, so
// only they can exit with status 5.
const (
	exitStatusStart = "Exit status: 0 success, 1 usage or local error, 2 server unreachable or not speaking CMP, " +
		"3 rejected by the CA, 4 protocol or verification failure, "
	exitStatusHelp       = exitStatusStart + "6 a response broke the strict profile."
	enrollExitStatusHelp = exitStatusStart + "5 issued but the confirmation failed, 6 a response broke the strict profile."
)

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
	case o.csr != "" && o.shapesTemplate():
		return errors.New("--subject, --san, --key-usage, --ext-key-usage and --template-cert cannot change " +
			"a request given with --csr")
	case o.templateCert != "" && o.reqType == typeKUR:
		return errors.New("a kur request renews the certificate in --cert, so --template-cert needs --type ir, cr or p10cr")
	case o.certReqID < 0:
		return errors.New("--cert-req-id must not be negative")
	case o.certReqID != 0 && o.reqType == typeP10CR:
		return errors.New("a p10cr request carries no certReqId, so --cert-req-id needs --type ir, cr or kur")
	case o.pollLater && o.capture == "":
		return errors.New("--poll-later records the transaction in the --capture file, so --capture is required")
	}
	if err := o.validateKey(); err != nil {
		return err
	}
	if err := o.format.validate(); err != nil {
		return err
	}
	if err := o.checkCapture(o.certOut, o.keyOut, o.chainOut); err != nil {
		return err
	}
	return checkOutputs(o.force, o.certOut, o.keyOut, o.chainOut)
}

// validateKey checks the flags that choose the key to certify and how it proves possession. A
// loaded --new-key is checked once it is read.
func (o *enrollOptions) validateKey() error {
	switch {
	case o.pop != "" && popMethods[o.pop] == 0:
		return fmt.Errorf("invalid --%s %q, want %s or %s", flagPOP, o.pop, popEncryptedCert, popChallenge)
	case o.pop != "" && o.csr != "":
		return fmt.Errorf("--%s is for keys that cannot sign, and a request given with --csr is signed", flagPOP)
	}
	if o.centralKeygen {
		return o.validateCentralKeygen()
	}
	generated := o.csr == "" && o.newKey == ""
	switch {
	case generated && o.keyOut == "":
		return errors.New("--key-out is required to save the generated key")
	case !generated && o.keyOut != "":
		return errors.New("--key-out is only used with a generated key")
	case !generated:
		return nil
	}
	t, err := keys.LookupType(o.keyType)
	if err != nil {
		return err
	}
	return o.checkPOP(t.Name, t.Signs)
}

// validateCentralKeygen checks the flags of a request that asks the CA to generate the key pair.
func (o *enrollOptions) validateCentralKeygen() error {
	switch {
	case o.reqType == typeP10CR:
		return fmt.Errorf("a p10cr request is signed with the key to certify, so --%s needs --type ir, cr or kur",
			flagCentralKeygen)
	case o.newKey != "":
		return fmt.Errorf("--%s asks the CA for the key, so --new-key cannot be used", flagCentralKeygen)
	case o.pop != "":
		return fmt.Errorf("--%s is for keys that cannot sign, and a key the CA generates needs no proof of possession",
			flagPOP)
	case o.keyOut == "":
		return errors.New("--key-out is required to save the key the CA generates")
	}
	_, err := keys.LookupType(o.keyType)
	return err
}

// checkPOP checks --pop and --type against whether keys of the type named name can sign.
func (o *enrollOptions) checkPOP(name string, signs bool) error {
	switch {
	case signs && o.pop != "":
		return fmt.Errorf("--%s is for keys that cannot sign, and %s keys sign their proof of possession", flagPOP, name)
	case !signs && o.reqType == typeP10CR:
		return fmt.Errorf("a p10cr request is signed with the key to certify, and %s keys cannot sign. "+
			"Use --type ir, cr or kur", name)
	}
	return nil
}

// indirectPOP returns the --pop method, encrypted-cert unless the flag names another.
func (o *enrollOptions) indirectPOP() client.IndirectPOP {
	if o.pop == "" {
		return client.EncryptedCertificate
	}
	return popMethods[o.pop]
}

// shapesTemplate reports whether a flag sets part of the certificate template.
func (o *enrollOptions) shapesTemplate() bool {
	return o.subject != "" || len(o.sans) > 0 || len(o.keyUsage) > 0 || len(o.extKeyUsage) > 0 || o.templateCert != ""
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
	// newKey is the key to certify: a crypto.Signer, or a crypto.Decapsulator for ML-KEM.
	newKey crypto.PrivateKey
	csrDER []byte
	// indirect is the proof of possession of a key that cannot sign, zero for a key that signs.
	indirect client.IndirectPOP
	// central asks the CA to generate the key pair, of the algorithm centralAlg or, when it is nil,
	// of the CA's choice. newKey is then nil.
	central    bool
	centralAlg *pkicmp.AlgorithmIdentifier
}

// runEnroll performs the enroll command.
func runEnroll(ctx context.Context, o *enrollOptions, p *printer, stdin io.Reader) error {
	if err := o.validate(); err != nil {
		return err
	}
	shape, err := o.readShape()
	if err != nil {
		return err
	}
	pr, err := o.load(stdin, p.stderr)
	if err != nil {
		return err
	}
	e := &enrollment{protected: pr}
	if err := o.prepareKey(e, stdin, p.stderr); err != nil {
		return err
	}
	if err := o.prepareTemplate(e, shape); err != nil {
		return err
	}
	if o.certProfile != "" {
		e.reqOpts = append(e.reqOpts, client.WithCertProfile(o.certProfile))
	}
	if o.certReqID != 0 {
		e.reqOpts = append(e.reqOpts, client.WithCertReqID(o.certReqID))
	}
	if o.implicitConfirm {
		e.reqOpts = append(e.reqOpts, client.WithImplicitConfirm())
	}
	if o.pollLater {
		e.reqOpts = append(e.reqOpts, client.WithDeferredPolling())
	}

	s, err := o.open(p, e.chain)
	if err != nil {
		return err
	}
	s.ra = e.ra
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
			return reportUnconfirmed(s, o.certOutputs, confErr, e.newKey)
		}
		if pendingErr, ok := errors.AsType[*client.PendingError](err); ok {
			return o.reportStillWaiting(s, e, pendingErr)
		}
		return s.fail(err)
	}
	if result.Pending != nil {
		return o.reportWaiting(s, e, result.Pending)
	}
	return reportIssued(s, o.certOutputs, result, e.newKey, o.implicitConfirm, e.indirect)
}

// reportIssued saves an issued certificate with its new key and the issuing CA certificates and
// reports it. The new key is key or the one the CA generated. implicitAsked says whether the request
// asked for implicit confirmation and pop how a key that cannot sign proved possession. The fields in
// extra follow those of the certificate.
func reportIssued(s *session, out certOutputs, result *client.EnrollResult, key crypto.PrivateKey, implicitAsked bool, pop client.IndirectPOP, extra ...ui.Field) error {
	cert := result.Certificate
	chain := issuerChain(cert, append(result.CAPubs, result.ExtraCertificates...))
	if result.GeneratedKey != nil {
		key = result.GeneratedKey
	}
	saved, err := out.save(cert, key, chain)
	if err != nil {
		return fmt.Errorf("the certificate was issued but could not be saved: %w", err)
	}
	if out.chainOut != "" && len(chain) == 0 {
		s.p.warn("The response carried no issuing CA certificates, so --chain-out was not written.")
	}
	status := lastStatus(s.recorder)
	fields := certificateFields(cert, status, saved)
	if confirmation := confirmation(result, implicitAsked); confirmation != "" {
		fields = append(fields, ui.Field{Name: fieldConfirmation, Value: confirmation})
	}
	if pop != 0 {
		fields = append(fields, ui.Field{Name: fieldPOP, Value: describeIndirectPOP(pop)})
	}
	kga := keyGenerationAuthority(result.GeneratedKey)
	if kga != "" {
		fields = append(fields, ui.Field{Name: fieldKeyGeneratedBy, Value: kga})
	}
	ra := s.registrationAuthority()
	if ra != "" {
		fields = append(fields, ui.Field{Name: fieldForwardedBy, Value: ra})
	}
	s.p.result("Certificate issued", append(fields, extra...), &enrollJSON{
		Status:                 status,
		Confirmed:              true,
		ImplicitConfirm:        result.ImplicitConfirm,
		ProofOfPossession:      popName(pop),
		CentralKeyGeneration:   result.GeneratedKey != nil,
		KeyGenerationAuthority: kga,
		RegistrationAuthority:  ra,
		Certificate:            certificateResult(cert),
		Chain:                  certificatesResult(chain),
		Saved:                  saved,
		TransactionID:          transactionID(s.recorder),
	})
	return nil
}

// registrationAuthority returns the subject of the registration authority certificate that forwarded
// the requests, "" when there is none.
func (s *session) registrationAuthority() string {
	if s.ra == nil {
		return ""
	}
	return ui.Sanitize(dn.Format(s.ra.RawSubject))
}

// keyGenerationAuthority returns the subject of the certificate that signed a key the CA generated,
// "" when there is none.
func keyGenerationAuthority(key *client.GeneratedKey) string {
	if key == nil || key.Signer == nil {
		return ""
	}
	return ui.Sanitize(dn.Format(key.Signer.RawSubject))
}

// popName returns the --pop value of an indirect proof of possession, "" for a signature.
func popName(pop client.IndirectPOP) string {
	for name, method := range popMethods {
		if method == pop {
			return name
		}
	}
	return ""
}

// describeIndirectPOP names how a key that cannot sign proved possession of its private key.
func describeIndirectPOP(pop client.IndirectPOP) string {
	if pop == client.ChallengeResponse {
		return "encrypted challenge"
	}
	return "encrypted certificate"
}

// confirmation describes how the certificate was confirmed when that differs from the usual certConf
// exchange, because the CA granted implicit confirmation or declined to grant the one asked for.
func confirmation(result *client.EnrollResult, implicitAsked bool) string {
	switch {
	case result.ImplicitConfirm:
		return "implicit, no certConf sent"
	case implicitAsked:
		return "certConf sent, because the CA did not grant implicit confirmation"
	}
	return ""
}

// reportWaiting handles a request that the CA keeps waiting under --poll-later. It saves the new key,
// records the transaction in the capture file and tells how to resume it.
func (o *enrollOptions) reportWaiting(s *session, e *enrollment, pending *client.PendingEnrollment) error {
	saved, err := o.saveKey(e.newKey)
	if err != nil {
		return fmt.Errorf("the request waits for the CA, but the key could not be saved: %w", err)
	}
	if err := o.recordPending(s, pending); err != nil {
		return fmt.Errorf("the request waits for the CA, but --capture could not record it: %w", err)
	}
	id := hex.EncodeToString(pending.TransactionID)
	fields := []ui.Field{
		{Name: fieldStatus, Value: pkicmp.StatusWaiting.String()},
		{Name: fieldTransactionID, Value: id},
		{Name: fieldNextPoll, Value: formatNextPoll(pending.NextPoll)},
		{Name: fieldSaved, Value: strings.Join(saved, ", ")},
		{Name: fieldNote, Value: resumeNote(id, o.capture)},
	}
	s.p.result("Request waiting for the CA", fields, waitingResult(saved, pending))
	return nil
}

// reportStillWaiting reports polling that ended while the CA still had the request waiting. With
// --capture the new key is saved and the transaction recorded, so poll can resume it.
func (o *enrollOptions) reportStillWaiting(s *session, e *enrollment, pendingErr *client.PendingError) error {
	if o.capture == "" {
		f := s.pendingFailure(pendingErr, "Record the run with --capture to collect a waiting certificate later with poll.")
		return s.p.fail(f, pendingErr)
	}
	saved, err := o.saveKey(e.newKey)
	if err == nil {
		err = o.recordPending(s, pendingErr.Pending)
	}
	if err != nil {
		f := s.pendingFailure(pendingErr, "The transaction could not be recorded for poll: "+err.Error())
		return s.p.fail(f, pendingErr)
	}
	f := s.pendingFailure(pendingErr, resumeNote(hex.EncodeToString(pendingErr.Pending.TransactionID), o.capture))
	s.p.doc.Result = waitingResult(saved, pendingErr.Pending)
	return s.p.fail(f, pendingErr, withSaved(f.fields(s.recording), saved)...)
}

// newKeyFile returns the file that holds the key to certify: --new-key or --key-out.
func (o *enrollOptions) newKeyFile() string {
	if o.newKey != "" {
		return o.newKey
	}
	return o.keyOut
}

// recordPending records pending in the capture file, so that poll can resume it.
func (o *enrollOptions) recordPending(s *session, pending *client.PendingEnrollment) error {
	rec, err := newPendingRecord(s, &o.protection, o.certOutputs, o.implicitConfirm, pending, o.newKeyFile())
	if err != nil {
		return err
	}
	return s.recordTransaction(capture.TransactionWaiting, pending.TransactionID, rec)
}

// reportUnconfirmed saves a certificate whose confirmation failed and explains the situation. The
// certificate is kept because retrying could issue a second one.
func reportUnconfirmed(s *session, out certOutputs, confErr *client.ConfirmationError, key crypto.PrivateKey) error {
	if confErr.GeneratedKey != nil {
		key = confErr.GeneratedKey
	}
	saved, saveErr := out.save(confErr.Certificate, key, nil)
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
		Status:                 lastStatus(s.recorder),
		CentralKeyGeneration:   confErr.GeneratedKey != nil,
		KeyGenerationAuthority: keyGenerationAuthority(confErr.GeneratedKey),
		RegistrationAuthority:  s.registrationAuthority(),
		Certificate:            certificateResult(confErr.Certificate),
		Chain:                  []*certificateJSON{},
		Saved:                  saved,
		TransactionID:          transactionID(s.recorder),
	}
	return s.p.fail(f, confErr, fields...)
}

// prepareKey loads or generates the key to certify. With --csr it loads the request that carries the
// key. The password of an encrypted --new-key may be prompted for on stdin. With --central-keygen
// it chooses the algorithm to ask the CA for instead.
func (o *enrollOptions) prepareKey(e *enrollment, stdin io.Reader, prompt io.Writer) error {
	switch {
	case o.centralKeygen:
		return o.prepareCentralKeygen(e)
	case o.csr != "":
		der, err := pemfile.ReadCSR(o.csr)
		if err != nil {
			return err
		}
		e.csrDER = der
	case o.newKey != "":
		key, err := o.keyPassword.load(o.newKey, stdin, prompt)
		if err != nil {
			return err
		}
		e.newKey = key
	default:
		key, err := keys.Generate(o.keyType)
		if err != nil {
			return err
		}
		e.newKey = key
	}
	if e.newKey == nil {
		return nil
	}
	pub := keys.Public(e.newKey)
	if _, signs := e.newKey.(crypto.Signer); !signs {
		if err := o.checkPOP(keys.Describe(pub), false); err != nil {
			return err
		}
		e.indirect = o.indirectPOP()
		return nil
	}
	if err := o.checkPOP(keys.Describe(pub), true); err != nil {
		return err
	}
	// The new key signs the proof of possession or the PKCS#10 request with the chosen digest.
	if o.hash != "" && !takesDigest(pub) {
		return fmt.Errorf("--hash applies to RSA and ECDSA keys, not to the %s key to certify", keys.Describe(pub))
	}
	return nil
}

// prepareCentralKeygen sets up a request that asks the CA to generate the key pair. The CA encrypts
// the private key for the protection, which a signing key can receive only when it is RSA or ECDSA.
func (o *enrollOptions) prepareCentralKeygen(e *enrollment) error {
	if sc, ok := e.creds.(*pkicmp.SignatureCredentials); ok {
		switch pub := sc.Key().Public().(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
		default:
			return fmt.Errorf("the CA encrypts the key it generates for --key, which an %s key cannot decrypt. "+
				"Sign with an RSA or ECDSA key or use a shared secret", keys.Describe(pub))
		}
	}
	e.central = true
	if o.keyTypeSet {
		t, err := keys.LookupType(o.keyType)
		if err != nil {
			return err
		}
		oid, params := t.Algorithm()
		e.centralAlg = &pkicmp.AlgorithmIdentifier{Algorithm: oid, Parameters: params}
	}
	return nil
}

// prepareTemplate sets the requested subject, subject alternative names and key usages. shape holds
// what --template-cert, --key-usage and --ext-key-usage ask for.
func (o *enrollOptions) prepareTemplate(e *enrollment, shape *templateShape) error {
	if o.csr != "" {
		return nil
	}
	var subject pkix.Name
	hasSubject := o.subject != ""
	hasSAN := len(o.sans) > 0 || shape.san != nil
	switch {
	case hasSubject:
		name, err := dn.ParseName(o.subject)
		if err != nil {
			return fmt.Errorf("--subject: %w", err)
		}
		subject = name
	case shape.subject != nil:
		subject, hasSubject = *shape.subject, true
	case o.reqType == typeKUR:
		// The key update repeats the subject of the old certificate.
		hasSubject = len(e.chain[0].Subject.Names) > 0
	case !hasSAN && o.ref != "":
		// RFC 9483 §4.1.5 lets a device that does not know its name use the reference instead.
		subject, hasSubject = pkix.Name{CommonName: o.ref}, true
	case !hasSAN:
		return errors.New("--subject or --san is required")
	}

	extensions, err := o.templateExtensions(shape, hasSubject)
	if err != nil {
		return err
	}
	if o.reqType == typeP10CR {
		signer, err := keys.Signer(e.newKey)
		if err != nil {
			return err
		}
		e.csrDER, err = createCSR(subject, extensions, signer, o.digest())
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

// createCSR returns a PKCS#10 request for key, signed with it. A non-zero hash selects the digest
// of the signature of an RSA or ECDSA key.
func createCSR(subject pkix.Name, extensions []pkix.Extension, key crypto.Signer, hash crypto.Hash) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            subject,
		ExtraExtensions:    extensions,
		SignatureAlgorithm: csrSignatureAlgorithm(key, hash),
	}
	der, err := compositex509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	return der, nil
}

// csrSignatureAlgorithm returns the PKCS#10 signature algorithm of key with the digest hash. It is
// unknown, which leaves the choice to crypto/x509, for a zero hash or a key that takes no digest.
func csrSignatureAlgorithm(key crypto.Signer, hash crypto.Hash) x509.SignatureAlgorithm {
	type pair struct{ rsa, ecdsa x509.SignatureAlgorithm }
	algorithms := map[crypto.Hash]pair{
		crypto.SHA1:   {x509.SHA1WithRSA, x509.ECDSAWithSHA1},
		crypto.SHA256: {x509.SHA256WithRSA, x509.ECDSAWithSHA256},
		crypto.SHA384: {x509.SHA384WithRSA, x509.ECDSAWithSHA384},
		crypto.SHA512: {x509.SHA512WithRSA, x509.ECDSAWithSHA512},
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return algorithms[hash].rsa
	case *ecdsa.PublicKey:
		return algorithms[hash].ecdsa
	}
	return x509.UnknownSignatureAlgorithm
}

// send performs the exchange for the requested type.
func (o *enrollOptions) send(ctx context.Context, c *client.Client, e *enrollment) (*client.EnrollResult, error) {
	if o.reqType == typeP10CR {
		return c.SendP10CR(ctx, e.csrDER, e.creds, e.reqOpts...)
	}
	if e.central {
		switch o.reqType {
		case typeCR:
			return c.SendCRWithCentralKeyGeneration(ctx, e.centralAlg, e.creds, e.reqOpts...)
		case typeKUR:
			return c.SendKURWithCentralKeyGeneration(ctx, e.centralAlg, e.creds, e.reqOpts...)
		default:
			return c.SendIRWithCentralKeyGeneration(ctx, e.centralAlg, e.creds, e.reqOpts...)
		}
	}
	if e.indirect != 0 {
		switch o.reqType {
		case typeCR:
			return c.SendCRWithIndirectPOP(ctx, e.newKey, e.indirect, e.creds, e.reqOpts...)
		case typeKUR:
			return c.SendKURWithIndirectPOP(ctx, e.newKey, e.indirect, e.creds, e.reqOpts...)
		default:
			return c.SendIRWithIndirectPOP(ctx, e.newKey, e.indirect, e.creds, e.reqOpts...)
		}
	}
	signer, err := keys.Signer(e.newKey)
	if err != nil {
		return nil, err
	}
	switch o.reqType {
	case typeCR:
		return c.SendCR(ctx, signer, e.creds, e.reqOpts...)
	case typeKUR:
		return c.SendKUR(ctx, signer, e.creds, e.reqOpts...)
	default:
		return c.SendIR(ctx, signer, e.creds, e.reqOpts...)
	}
}

// save writes the key, then the certificate and the chain. It returns the paths written. The key
// comes first so that a certificate file never exists without its key.
func (o *certOutputs) save(cert *x509.Certificate, key crypto.PrivateKey, chain []*x509.Certificate) ([]string, error) {
	saved, err := o.saveKey(key)
	if err != nil {
		return saved, err
	}
	if err := pemfile.Write(o.certOut, o.format.certificate(cert), 0o644, o.force); err != nil {
		return saved, err
	}
	saved = append(saved, o.certOut)
	if o.chainOut != "" && len(chain) > 0 {
		data, err := o.format.certificates(chain)
		if err != nil {
			return saved, err
		}
		if err := pemfile.Write(o.chainOut, data, 0o644, o.force); err != nil {
			return saved, err
		}
		saved = append(saved, o.chainOut)
	}
	return saved, nil
}

// saveKey writes a new key to --key-out. It returns the paths written, none when there is no key to
// save.
func (o *certOutputs) saveKey(key crypto.PrivateKey) ([]string, error) {
	if o.keyOut == "" || key == nil {
		return []string{}, nil
	}
	data, err := o.format.key(key)
	if err != nil {
		return []string{}, err
	}
	if err := pemfile.Write(o.keyOut, data, 0o600, o.force); err != nil {
		return []string{}, err
	}
	return []string{o.keyOut}, nil
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

// transactionID returns the transaction ID of the first request in hex. It returns "" when no request
// was sent.
func transactionID(r *trace.Recorder) string {
	for _, ev := range r.Events() {
		if ev.Kind == trace.Request && ev.Message != nil {
			return hex.EncodeToString(ev.Message.TransactionID)
		}
	}
	return ""
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
		ui.Field{Name: fieldStatus, Value: status},
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
		{Name: fieldSubject, Value: ui.Sanitize(dn.Format(cert.RawSubject))},
		{Name: "Alt names", Value: ui.Sanitize(strings.Join(altNames(cert), ", "))},
		{Name: fieldIssuer, Value: ui.Sanitize(dn.Format(cert.RawIssuer))},
		{Name: fieldSerial, Value: formatSerial(cert)},
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
