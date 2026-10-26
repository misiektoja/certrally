package cli

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/capture"
	"github.com/misiektoja/certrally/internal/profile"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// pollOptions holds the poll command line.
type pollOptions struct {
	outputOptions
	transactionID string
	capture       string
	server        string
	secretFile    string
	keyPassword
	// newKey is the private key of a request that proves possession with an encrypted certificate.
	newKey   string
	insecure bool
	proxy    string
	timeout  time.Duration
	certOut  string
	chainOut string
	force    bool
	format   outFormat
}

// newPollCommand returns the poll command.
func newPollCommand() *cobra.Command {
	o := &pollOptions{}
	cmd := &cobra.Command{
		Use:   "poll --transaction-id ID --capture FILE [flags]",
		Short: "Collect a certificate that the CA kept waiting",
		Long: "Collect the certificate of an enrollment that the CA answered with status waiting.\n\n" +
			"enroll --poll-later stops at that answer and records the transaction in its --capture file, as " +
			"does an enroll whose polling ends at --timeout. poll reads the transaction from that file, polls " +
			"until the CA decides, confirms the certificate and saves it where enroll was asked to, unless " +
			"--cert-out or --chain-out names another file. The run is appended to the same file.\n\n" +
			"The server, the protection and the trusted CA certificates come from the enroll run. The shared " +
			"secret is read again from --secret-file, the CERTRALLY_SECRET environment variable or a prompt. " +
			"A poll that ends while the CA still waits records the new state, so the same command can run " +
			"again.\n\n" +
			"A request whose key cannot sign and proves possession with an encrypted certificate needs that key " +
			"to read the certificate. poll reads it from the file enroll saved or read, or from --new-key.\n\n" +
			enrollExitStatusHelp,
		Example: "  certrally enroll --server https://ca.example.com/.well-known/cmp --ref device-42 \\\n" +
			"    --subject CN=device-42 --cert-out device.pem --key-out device.key \\\n" +
			"    --poll-later --capture device.jsonl\n\n" +
			"  certrally poll --transaction-id 5d41402abc4b2a76b9719d911017c592 --capture device.jsonl",
		Args: cobra.NoArgs,
		RunE: runWith(&o.outputOptions, func(cmd *cobra.Command, _ []string, p *printer) error {
			return runPoll(cmd.Context(), o, p, cmd.InOrStdin())
		}),
	}
	o.outputOptions.addFlags(cmd)
	f := cmd.Flags()
	f.StringVar(&o.transactionID, "transaction-id", "", "transaction ID that enroll printed, in hex")
	f.StringVar(&o.capture, "capture", "", "capture file of the enroll run, to which this run is appended")
	f.StringVar(&o.server, flagServer, "", "address of the CMP server, when it is not the one enroll used")
	f.StringVar(&o.secretFile, "secret-file", "", "read the shared secret from a file, or - for standard input")
	o.keyPassword.addFlags(cmd)
	f.StringVar(&o.newKey, "new-key", "",
		"private key of the request, when it is not in the file enroll saved or read (encrypted-cert requests)")
	f.BoolVar(&o.insecure, flagInsecure, false, insecureHelp)
	f.StringVar(&o.proxy, flagProxy, "", proxyHelp)
	f.DurationVar(&o.timeout, flagTimeout, 5*time.Minute, "limit for polling and the confirmation")
	f.StringVar(&o.certOut, "cert-out", "", "write the issued certificate to this file instead of the one enroll named")
	f.StringVar(&o.chainOut, "chain-out", "",
		"write the issuing CA certificates from the response to this file instead of the one enroll named")
	o.format.addFlags(cmd, "", "format of the output files instead of the one enroll used: pem or der")
	f.BoolVar(&o.force, "force", false, "replace existing output files")
	_ = cmd.MarkFlagRequired("transaction-id")
	_ = cmd.MarkFlagRequired("capture")
	for _, name := range []string{"transaction-id", flagServer, flagTimeout, flagProxy} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// pendingRecord is what poll needs to resume an enrollment that the CA has not decided. It is the
// resume member of a waiting transaction line in the capture file. Paths are absolute, so poll can
// run in another directory. The shared secret and the private keys are not part of it.
type pendingRecord struct {
	// Server is the server URL without any password.
	Server  string `json:"server"`
	Profile string `json:"profile"`
	// Ref, MAC, Iterations and Hash rebuild the shared-secret protection. Cert and Key name the
	// files of the signing protection instead. Hash also selects the digest of its signatures.
	Ref        string `json:"ref,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Cert       string `json:"cert,omitempty"`
	Key        string `json:"key,omitempty"`
	// CACerts holds the --ca-cert certificates, Anchors every certificate the run trusted and
	// TLSCACerts the --tls-ca-cert certificates, as DER.
	CACerts    [][]byte `json:"caCerts,omitempty"`
	Anchors    [][]byte `json:"anchors,omitempty"`
	TLSCACerts [][]byte `json:"tlsCaCerts,omitempty"`
	// CertOut and ChainOut are the files enroll was asked to write the certificate and chain to.
	CertOut  string `json:"certOut"`
	ChainOut string `json:"chainOut,omitempty"`
	// OutFormat is the --out-format of the enroll run.
	OutFormat string `json:"outFormat,omitempty"`
	// ImplicitConfirm records that the request asked for implicit confirmation.
	ImplicitConfirm bool `json:"implicitConfirm,omitempty"`
	// NewKey is the file of the key to certify when it proves possession with an encrypted
	// certificate, which only that key can decrypt.
	NewKey string `json:"newKey,omitempty"`
	// State is the transaction state of go-pki-cmp.
	State *client.PendingEnrollment `json:"state"`
}

// newPendingRecord collects what poll needs to resume pending, which an enroll run with the
// protection prot and the outputs out started in s. newKeyFile holds the key to certify.
func newPendingRecord(s *session, prot *protection, out certOutputs, implicitConfirm bool, pending *client.PendingEnrollment, newKeyFile string) (*pendingRecord, error) {
	rec := &pendingRecord{
		Server:          s.server,
		Profile:         s.profile,
		Iterations:      prot.iterations,
		Hash:            prot.hash,
		ImplicitConfirm: implicitConfirm,
		State:           pending,
	}
	if prot.signed() {
		rec.Cert, rec.Key = prot.certFile, prot.keyFile
	} else {
		rec.Ref, rec.MAC = prot.ref, prot.mac
	}
	rec.CertOut, rec.ChainOut, rec.OutFormat = out.certOut, out.chainOut, out.format.name
	if pending.IndirectPOP == client.EncryptedCertificate {
		rec.NewKey = newKeyFile
	}
	for _, path := range []*string{&rec.Cert, &rec.Key, &rec.CertOut, &rec.ChainOut, &rec.NewKey} {
		if *path == "" || *path == stdoutPath {
			continue
		}
		abs, err := filepath.Abs(*path)
		if err != nil {
			return nil, err
		}
		*path = abs
	}
	trust := s.saveTrust()
	rec.CACerts = certificatesDER(trust.caCerts)
	rec.Anchors = certificatesDER(trust.anchors)
	rec.TLSCACerts = certificatesDER(trust.tlsRoots)
	return rec, nil
}

// certificatesDER returns the DER of certs.
func certificatesDER(certs []*x509.Certificate) [][]byte {
	der := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		der = append(der, cert.Raw)
	}
	return der
}

// parseCertificatesDER parses certificates saved by certificatesDER.
func parseCertificatesDER(ders [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// trust returns the trust of the enroll run.
func (r *pendingRecord) trust() (*savedTrust, error) {
	caCerts, err := parseCertificatesDER(r.CACerts)
	if err != nil {
		return nil, fmt.Errorf("the CA certificates of the transaction: %w", err)
	}
	anchors, err := parseCertificatesDER(r.Anchors)
	if err != nil {
		return nil, fmt.Errorf("the trusted certificates of the transaction: %w", err)
	}
	tlsRoots, err := parseCertificatesDER(r.TLSCACerts)
	if err != nil {
		return nil, fmt.Errorf("the HTTPS CA certificates of the transaction: %w", err)
	}
	return &savedTrust{caCerts: caCerts, anchors: anchors, tlsRoots: tlsRoots}, nil
}

// protection returns the protection of the enroll run, with the shared secret read from secretFile
// and the password of an encrypted key from password.
func (r *pendingRecord) protection(secretFile string, password keyPassword) *protection {
	return &protection{
		ref:         r.Ref,
		mac:         r.MAC,
		secretFile:  secretFile,
		certFile:    r.Cert,
		keyFile:     r.Key,
		keyPassword: password,
		iterations:  r.Iterations,
		hash:        r.Hash,
	}
}

// waitingResult is the JSON result for a request the CA keeps waiting.
func waitingResult(saved []string, pending *client.PendingEnrollment) *enrollJSON {
	return &enrollJSON{
		Status:        "waiting",
		Chain:         []*certificateJSON{},
		Saved:         saved,
		TransactionID: hex.EncodeToString(pending.TransactionID),
		NextPoll:      pending.NextPoll.UTC(),
	}
}

// resumeNote tells how to resume the transaction id recorded in captureFile.
func resumeNote(id, captureFile string) string {
	return fmt.Sprintf("Collect the certificate with: %s poll --transaction-id %s --capture %s",
		programName, id, shellQuote(captureFile))
}

// formatNextPoll returns when the CA asked for the next poll. It returns "" when the CA named no time.
func formatNextPoll(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// withSaved adds the saved files to the fields of a failure, before its note.
func withSaved(fields []ui.Field, saved []string) []ui.Field {
	if len(saved) == 0 || len(fields) == 0 {
		return fields
	}
	last := len(fields) - 1
	return slices.Insert(fields, last, ui.Field{Name: fieldSaved, Value: strings.Join(saved, ", ")})
}

// parseTransactionID parses a transaction ID in hex, with or without colons, and returns it in the
// lower-case form of capture files.
func parseTransactionID(s string) (string, error) {
	der, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(der) == 0 {
		return "", fmt.Errorf("--transaction-id %q is not a transaction ID in hex", s)
	}
	return hex.EncodeToString(der), nil
}

// readPendingRecord returns the latest state of the transaction id in the capture file at path.
func readPendingRecord(path, id string) (*pendingRecord, error) {
	t, err := capture.FindTransaction(path, id)
	switch {
	case errors.Is(err, capture.ErrNoTransaction):
		return nil, fmt.Errorf("%s holds no transaction %s. Pass the --capture file of the enroll run", path, id)
	case errors.Is(err, capture.ErrNotWaiting):
		return nil, fmt.Errorf("transaction %s did not wait for the CA, so there is nothing to collect. "+
			"The enroll run reported its outcome", id)
	case err != nil:
		return nil, fmt.Errorf("--capture: %w", err)
	case t.State == capture.TransactionEnded:
		return nil, fmt.Errorf("transaction %s already ended at %s", id, t.Time.UTC().Format(timeLayout))
	case t.State != capture.TransactionWaiting || len(t.Resume) == 0:
		return nil, fmt.Errorf("%s: transaction %s has no state to resume", path, id)
	}
	var rec pendingRecord
	if err := json.Unmarshal(t.Resume, &rec); err != nil {
		return nil, fmt.Errorf("%s: transaction %s: %w", path, id, err)
	}
	if rec.State == nil {
		return nil, fmt.Errorf("%s: transaction %s has no state to resume", path, id)
	}
	return &rec, nil
}

// connection returns how to reach the server of rec, with --server taking precedence.
func (o *pollOptions) connection(rec *pendingRecord) (*connection, error) {
	server := o.server
	if server == "" {
		server = rec.Server
		if u, err := url.Parse(server); err == nil && u.User != nil {
			if _, hasPassword := u.User.Password(); hasPassword {
				return nil, errors.New("the capture file holds the server URL without its password, so pass --server again")
			}
		}
	}
	if !isServerURL(server) {
		return nil, fmt.Errorf("--server %q is not an http or https URL", server)
	}
	if o.timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}
	if _, err := parseProxy(o.proxy); err != nil {
		return nil, err
	}
	if err := o.checkStdin("--secret-file", o.secretFile); err != nil {
		return nil, err
	}
	if !slices.Contains(profile.Names, rec.Profile) {
		return nil, fmt.Errorf("the transaction names an unknown profile %q", rec.Profile)
	}
	trust, err := rec.trust()
	if err != nil {
		return nil, err
	}
	return &connection{
		server:   server,
		insecure: o.insecure,
		proxy:    o.proxy,
		timeout:  o.timeout,
		capture:  o.capture,
		profile:  rec.Profile,
		resumed:  trust,
	}, nil
}

// outputs returns where and how to save the certificate of rec, with --cert-out, --chain-out and
// --out-format taking precedence.
func (o *pollOptions) outputs(rec *pendingRecord) certOutputs {
	out := certOutputs{
		certOut:  rec.CertOut,
		chainOut: rec.ChainOut,
		force:    o.force,
		format:   outFormat{name: rec.OutFormat},
	}
	if o.format.name != "" {
		out.format = o.format
	}
	if o.certOut != "" {
		out.certOut = o.certOut
	}
	if o.chainOut != "" {
		out.chainOut = o.chainOut
	}
	return out
}

// runPoll performs the poll command.
func runPoll(ctx context.Context, o *pollOptions, p *printer, stdin io.Reader) error {
	id, err := parseTransactionID(o.transactionID)
	if err != nil {
		return err
	}
	rec, err := readPendingRecord(o.capture, id)
	if err != nil {
		return err
	}
	conn, err := o.connection(rec)
	if err != nil {
		return err
	}
	if err := o.format.validate(); err != nil {
		return err
	}
	out := o.outputs(rec)
	if out.certOut == "" {
		return errors.New("the transaction names no certificate file, so --cert-out is required")
	}
	if err := conn.checkCapture(out.certOut, out.chainOut); err != nil {
		return err
	}
	if err := checkOutputs(out.force, out.certOut, out.chainOut); err != nil {
		return err
	}
	pr, err := rec.protection(o.secretFile, o.keyPassword).load(stdin, p.stderr)
	if err != nil {
		return err
	}
	newKey, err := o.loadNewKey(rec, stdin, p.stderr)
	if err != nil {
		return err
	}
	s, err := conn.open(p, pr.chain)
	if err != nil {
		return err
	}
	c, err := s.client(pr.clientOpts...)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	s.startLadder()
	var result *client.EnrollResult
	if newKey != nil {
		result, err = c.ResumeEnrollmentWithIndirectPOP(ctx, rec.State, newKey, pr.creds)
	} else {
		result, err = c.ResumeEnrollment(ctx, rec.State, pr.creds)
	}
	s.endLadder()
	if pendingErr, ok := errors.AsType[*client.PendingError](err); ok {
		return o.reportStillWaiting(s, rec, pendingErr)
	}
	if !transactionEnded(s.recorder, err) {
		f := s.failure(err)
		if f.Note == "" {
			f.Note = "The transaction stays recorded, so the same poll command can run again."
		}
		return s.p.fail(f, err)
	}
	// A later poll of an ended transaction is refused before anything is sent.
	if recErr := s.recordTransaction(capture.TransactionEnded, rec.State.TransactionID, nil); recErr != nil {
		p.warn("The capture file could not record that the transaction ended: " + recErr.Error())
	}
	if err != nil {
		if confErr, ok := errors.AsType[*client.ConfirmationError](err); ok {
			return reportUnconfirmed(s, out, confErr, nil)
		}
		return s.fail(err)
	}
	return reportIssued(s, out, result, nil, rec.ImplicitConfirm, rec.State.IndirectPOP,
		ui.Field{Name: fieldTransactionID, Value: id})
}

// loadNewKey reads the key to certify of a request that proves possession with an encrypted
// certificate, from --new-key or the file enroll recorded. It returns nil for other requests.
func (o *pollOptions) loadNewKey(rec *pendingRecord, stdin io.Reader, prompt io.Writer) (crypto.PrivateKey, error) {
	if rec.State.IndirectPOP != client.EncryptedCertificate {
		if o.newKey != "" {
			return nil, errors.New("--new-key is only used for a request that proves possession with an encrypted certificate")
		}
		return nil, nil
	}
	path := o.newKey
	if path == "" {
		path = rec.NewKey
	}
	if path == "" || path == stdoutPath {
		return nil, errors.New("the CA encrypts the certificate for the key of the request, so --new-key must name that key")
	}
	key, err := o.keyPassword.load(path, stdin, prompt)
	if errors.Is(err, fs.ErrNotExist) && o.newKey == "" {
		return nil, fmt.Errorf("%w. The CA encrypts the certificate for the key of the request, "+
			"so name that key with --new-key", err)
	}
	return key, err
}

// transactionEnded reports whether err, the outcome of a resumed enrollment recorded by r, ended the
// transaction at the CA: the certificate was issued or a verified certificate response rejected the
// request. After other failures, such as a wrong shared secret, the CA still holds the request.
func transactionEnded(r *trace.Recorder, err error) bool {
	if err == nil {
		return true
	}
	if _, ok := errors.AsType[*client.ConfirmationError](err); ok {
		return true
	}
	if _, ok := errors.AsType[*pkicmp.PKIStatusError](err); !ok {
		return false
	}
	for _, ev := range slices.Backward(r.Events()) {
		if ev.Kind == trace.Response && ev.Message != nil {
			switch ev.Message.Body {
			case pkicmp.BodyTypeIP.String(), pkicmp.BodyTypeCP.String(), pkicmp.BodyTypeKUP.String():
				return ev.Message.Status == pkicmp.StatusRejection.String()
			}
			return false
		}
	}
	return false
}

// reportStillWaiting records the new state of a transaction the CA still keeps waiting and reports it.
func (o *pollOptions) reportStillWaiting(s *session, rec *pendingRecord, pendingErr *client.PendingError) error {
	next := *rec
	next.State = pendingErr.Pending
	note := "Run the same poll command again later to collect the certificate."
	if err := s.recordTransaction(capture.TransactionWaiting, next.State.TransactionID, &next); err != nil {
		note = "The new state of the transaction could not be recorded: " + err.Error()
	}
	f := s.pendingFailure(pendingErr, note)
	s.p.doc.Result = waitingResult([]string{}, pendingErr.Pending)
	return s.p.fail(f, pendingErr)
}
