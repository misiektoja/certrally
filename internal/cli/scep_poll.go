package cli

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/misiektoja/go-scep"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/keys"
)

// scepPollOptions holds the scep poll command line.
type scepPollOptions struct {
	scepConnection
	outputOptions
	keyPassword
	state string
	// once sends one CertPoll instead of polling until the CA decides.
	once         bool
	pollInterval time.Duration
}

// newSCEPPollCommand returns scep poll.
func newSCEPPollCommand() *cobra.Command {
	o := &scepPollOptions{}
	cmd := &cobra.Command{
		Use:   "poll --state FILE [flags]",
		Short: "Collect a certificate that the CA kept pending",
		Long: "Continue a request that a SCEP server answered PENDING. The --state file that certrally scep enroll " +
			"or scep renew wrote holds the request, the certificate that signs it, the CA certificates and where " +
			"to save the result. certrally sends CertPoll (RFC 8894 section 3.3.3) every --poll-interval until " +
			"the CA decides, within --timeout. --once sends a single CertPoll.\n\n" +
			"The state file is removed once the CA issues or rejects the certificate. --server, --ca and " +
			"--allow-des replace the values of the state file.\n\n" + scepExitStatusHelp,
		Example: "  certrally scep poll --state device.pem.state",
		Args:    cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runSCEPPoll(cmd, o, p)
		}),
	}
	o.scepConnection.addFlags(cmd, 5*time.Minute, scepEnrollTimeoutHelp, true)
	o.addDecryptFlags(cmd)
	o.outputOptions.addFlags(cmd)
	o.keyPassword.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.state, "state", "", "state file that certrally scep enroll or scep renew wrote")
	f.BoolVar(&o.once, "once", false, "send one CertPoll and stop, even when the CA answers PENDING")
	f.DurationVar(&o.pollInterval, "poll-interval", 30*time.Second, "wait between polls while the CA answers PENDING")
	_ = cmd.MarkFlagRequired("state")
	_ = cmd.RegisterFlagCompletionFunc("poll-interval", cobra.NoFileCompletions)
	return cmd
}

// runSCEPPoll performs scep poll.
func runSCEPPoll(cmd *cobra.Command, o *scepPollOptions, p *printer) error {
	state, err := readSCEPState(o.state)
	if err != nil {
		return err
	}
	if !cmd.Flags().Changed(flagServer) {
		o.server = state.Server
	}
	if !cmd.Flags().Changed(flagCAName) {
		o.caName = state.CAName
	}
	if !cmd.Flags().Changed(flagAllowDES) {
		o.allowDES = state.AllowDES
	}
	if err := o.scepConnection.validate(); err != nil {
		return err
	}
	if o.pollInterval <= 0 {
		return errors.New("--poll-interval must be positive")
	}
	if err := o.checkCapture(state.CertOut, state.ChainOut, o.state); err != nil {
		return err
	}
	req, caCerts, err := state.request(&o.keyPassword, cmd.InOrStdin(), p.stderr)
	if err != nil {
		return fmt.Errorf("%s: %w", o.state, err)
	}
	format := outFormat{name: state.OutFormat}
	if err := format.validate(); err != nil {
		return fmt.Errorf("%s: %w", o.state, err)
	}
	s, err := o.scepConnection.open(p)
	if err != nil {
		return err
	}
	ca, err := s.caCertificates(cmd.Context(), caCerts, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", o.state, err)
	}
	w := &scepWait{s: s, interval: o.pollInterval, pollLater: o.once, kept: true}
	err = s.run(cmd.Context(), func(ctx context.Context) error { return w.poll(ctx, ca, req) })
	if _, rejected := errors.AsType[*scepFailureError](err); rejected {
		if rerr := removeSCEPState(o.state); rerr != nil {
			p.warn("The rejected request is still in " + o.state + ": " + rerr.Error())
		}
	}
	if err != nil {
		return err
	}
	out := &scepOutputs{
		certOut:  state.CertOut,
		chainOut: state.ChainOut,
		keyOut:   state.KeyOut,
		state:    o.state,
		format:   format,
	}
	title := titleCertificateIssued
	if req.messageType == scep.RenewalReq {
		title = titleCertificateRenewed
	}
	return out.report(s, req, w, title)
}

// readSCEPState reads a --state file.
func readSCEPState(path string) (*scepState, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the user names the file to read.
	if err != nil {
		return nil, err
	}
	var state scepState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("%s is not a SCEP state file: %w", path, err)
	}
	if state.Version != scepStateVersion {
		return nil, fmt.Errorf("%s has state version %d, which this certrally does not read", path, state.Version)
	}
	if state.Server == "" || state.CertOut == "" || state.TransactionID == "" {
		return nil, fmt.Errorf("%s is not a SCEP state file: it names no server, transaction or --cert-out", path)
	}
	return &state, nil
}

// request rebuilds the pending request and returns it with the CA certificates it was sent to. The
// password of an encrypted signer key file may be prompted for on stdin.
func (st *scepState) request(kp *keyPassword, stdin io.Reader, prompt io.Writer) (*scepRequest, []*x509.Certificate, error) {
	req := &scepRequest{transactionID: scep.TransactionID(st.TransactionID)}
	switch st.MessageType {
	case "PKCSReq":
		req.messageType = scep.PKCSReq
	case "RenewalReq":
		req.messageType = scep.RenewalReq
	default:
		return nil, nil, fmt.Errorf("unknown message type %q", st.MessageType)
	}
	var err error
	if req.digest, err = scepHash(st.Digest); err != nil {
		return nil, nil, err
	}
	if req.cipher, err = scepCipher(st.Cipher); err != nil {
		return nil, nil, err
	}
	csrDER, err := pemBlock(st.CSR, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, nil, err
	}
	if req.csr, err = x509.ParseCertificateRequest(csrDER); err != nil {
		return nil, nil, err
	}
	signerDER, err := pemBlock(st.SignerCertificate, "CERTIFICATE")
	if err != nil {
		return nil, nil, err
	}
	if req.signerCert, err = x509.ParseCertificate(signerDER); err != nil {
		return nil, nil, err
	}
	var signer crypto.Signer
	if st.SignerKey != "" {
		key, err := keys.Parse([]byte(st.SignerKey))
		if err != nil {
			return nil, nil, fmt.Errorf("signer key: %w", err)
		}
		signer, _ = key.(crypto.Signer)
	} else if signer, err = kp.loadSigner(st.SignerKeyFile, stdin, prompt); err != nil {
		return nil, nil, err
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok || !publicKeyEqual(signer.Public(), req.signerCert.PublicKey) {
		return nil, nil, errors.New("the signer key is not the RSA key of the signer certificate")
	}
	req.signerKey, req.signerKeyFile = signer, st.SignerKeyFile
	caCerts, err := parsePEMCertificates(st.CACertificates)
	if err != nil {
		return nil, nil, err
	}
	return req, caCerts, nil
}

// pemBlock returns the DER of the single PEM block of type typ in text.
func pemBlock(text, typ string) ([]byte, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("no %s", typ)
	}
	return block.Bytes, nil
}

// parsePEMCertificates parses the PEM certificates in text.
func parsePEMCertificates(text string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CA certificates")
	}
	return certs, nil
}
