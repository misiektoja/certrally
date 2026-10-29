package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/misiektoja/go-scep/scepserver"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/scepca"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// scepMockPath is the path of the SCEP URL that the test CA prints. It answers on every path.
const scepMockPath = "/scep"

// scepMockOptions holds the scep mock command line.
type scepMockOptions struct {
	listen        string
	caName        string
	challenge     secret.Value
	challengeFile string
	anyChallenge  bool
	pendingPolls  int
	ra            bool
	nextCA        bool
	busyInterval  time.Duration
	caps          []string
	caOut         string
	force         bool
}

// newSCEPMockCommand returns scep mock.
func newSCEPMockCommand() *cobra.Command {
	o := &scepMockOptions{}
	cmd := &cobra.Command{
		Use:   mockUse,
		Short: "Run a local SCEP test CA",
		Long: "Run a SCEP test CA on this machine, to try certrally or test scripts without a real CA. It answers " +
			"GetCACaps, GetCACert, GetCACertChain and PKIOperation with PKCSReq, RenewalReq, CertPoll, GetCert " +
			"and GetCRL over plain HTTP. With --next-ca it answers GetNextCACert too.\n\n" +
			"A PKCSReq must carry the challenge password from --challenge, --challenge-file or " +
			secret.ChallengeEnvVar + ". Without any of them, a random challenge is generated and printed. " +
			"--any-challenge issues whatever challenge a request carries. A RenewalReq must be signed with a " +
			"valid certificate of the CA. --pending-polls answers every new request with PENDING until the " +
			"client has polled that many times. The CA keys and everything the CA issued live in memory and are " +
			"lost when it stops. Stop it with Ctrl-C.",
		Example: "  certrally scep mock\n" +
			"  certrally scep mock --ca-name 'Issuing CA' --challenge-file challenge.txt --ca-out ca.pem\n" +
			"  certrally scep mock --any-challenge --pending-polls 2 --busy-interval 2s",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSCEPMock(cmd, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.listen, flagListen, "127.0.0.1:8090", "address and port to listen on. Port 0 picks a free port")
	f.StringVar(&o.caName, "ca-name", "", "answer GetCACert only for this CA name, as a server with several CAs does")
	f.Var(&o.challenge, "challenge",
		"challenge password that a PKCSReq must carry, which other users of this machine can see in the process list")
	f.StringVar(&o.challengeFile, "challenge-file", "", "read the challenge password from a file, or - for standard input")
	f.BoolVar(&o.anyChallenge, "any-challenge", false, "issue whatever challenge password a request carries")
	cmd.MarkFlagsMutuallyExclusive("challenge", "challenge-file", "any-challenge")
	f.IntVar(&o.pendingPolls, "pending-polls", 0,
		"answer every new request with PENDING and issue the certificate at this CertPoll")
	f.BoolVar(&o.ra, "ra", false, "decrypt requests and sign answers with a separate RA certificate")
	f.BoolVar(&o.nextCA, "next-ca", false, "announce a next CA certificate through GetNextCACert")
	f.DurationVar(&o.busyInterval, "busy-interval", 0,
		"answer HTTP 503 without Retry-After to a PKIOperation sent within this time of the previous one")
	f.StringSliceVar(&o.caps, "caps", nil,
		"replace the GetCACaps answer with these capabilities, such as SHA-1,DES3 for an old CA")
	f.StringVar(&o.caOut, "ca-out", "", "save the GetCACert certificates to this file, for --ca-cert")
	f.BoolVar(&o.force, "force", false, "replace an existing --ca-out file")
	for _, name := range []string{flagListen, "ca-name", "challenge", "pending-polls", "busy-interval", "caps"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// readChallenge reads the challenge from --challenge, --challenge-file or the environment. It
// generates a random one instead of prompting, because the user needs to know it to use it. With
// --any-challenge there is no challenge to check.
func (o *scepMockOptions) readChallenge(stdin io.Reader) (mockSecret, error) {
	if o.anyChallenge {
		return mockSecret{}, nil
	}
	src := secret.Source{
		Kind:      secret.Challenge,
		Value:     o.challenge.Bytes(),
		File:      o.challengeFile,
		LookupEnv: os.LookupEnv,
	}
	if o.challengeFile == stdoutPath {
		src.Stdin = stdin
	}
	value, err := src.Read()
	switch {
	case err == nil:
		return mockSecret{value: value}, nil
	case !errors.Is(err, secret.ErrMissing):
		return mockSecret{}, err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return mockSecret{}, err
	}
	return mockSecret{value: []byte(hex.EncodeToString(random)), generated: true}, nil
}

// runSCEPMock serves the SCEP test CA until the context ends or the process is interrupted.
func runSCEPMock(cmd *cobra.Command, o *scepMockOptions) error {
	if o.pendingPolls < 0 {
		return errors.New("--pending-polls must not be negative")
	}
	if o.busyInterval < 0 {
		return errors.New("--busy-interval must not be negative")
	}
	p := newPrinter(cmd, outputOptions{})
	if err := p.confirmOutputs(&o.force, o.caOut); err != nil {
		return err
	}
	challenge, err := o.readChallenge(cmd.InOrStdin())
	if err != nil {
		return err
	}
	if !o.anyChallenge && len(challenge.value) == 0 {
		return errors.New("the challenge password must not be empty. --any-challenge accepts every request")
	}
	ca, err := scepca.New(scepca.Options{
		Name:         o.caName,
		Challenge:    challenge.value,
		PendingPolls: o.pendingPolls,
		RA:           o.ra,
		NextCA:       o.nextCA,
		BusyInterval: o.busyInterval,
	})
	if err != nil {
		return err
	}
	handler, err := ca.Handler(scepserver.Options{
		Capabilities: o.caps,
		AllowMD5:     true,
		Logger:       slog.New(scepMockNotes{}),
	})
	if err != nil {
		return err
	}
	caCerts, _ := ca.CACertificates(cmd.Context(), o.caName)

	ln, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", o.listen)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	// The CA file is written once the address is taken, so a failed start leaves no file behind.
	if o.caOut != "" {
		if err := pemfile.Write(o.caOut, pemfile.EncodeCertificates(caCerts), 0o644, o.force); err != nil {
			_ = ln.Close()
			return err
		}
	}
	hostPort, remote := mockHostPort(ln.Addr())
	url := "http://" + hostPort + scepMockPath
	o.report(p, url, caCerts[0], challenge)
	if remote {
		p.warn("The mock CA accepts requests from other hosts over plain HTTP. " +
			"Anyone who reaches it and knows the challenge password gets certificates.")
	}

	srv := &http.Server{
		Handler:           &scepMockLog{next: handler, p: p},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	var serveErr error
	select {
	case serveErr = <-served:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil && serveErr == nil {
		serveErr = err
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	p.line("Mock CA stopped")
	return nil
}

// report prints how to reach the test CA and the commands that work against it. caCert is the
// issuing CA certificate.
func (o *scepMockOptions) report(p *printer, url string, caCert *x509.Certificate, challenge mockSecret) {
	challengeField := "from " + secret.ChallengeEnvVar
	switch {
	case o.anyChallenge:
		challengeField = "any"
	case challenge.generated:
		challengeField = string(challenge.value) + " (generated)"
	case o.challenge.Bytes() != nil:
		challengeField = "from --challenge"
	case o.challengeFile != "":
		challengeField = "from " + o.challengeFile
	}
	pending := "no"
	if o.pendingPolls > 0 {
		pending = count(o.pendingPolls, "poll", "polls")
	}
	sum := sha256.Sum256(caCert.Raw)
	p.result("SCEP mock CA running", []ui.Field{
		{Name: fieldServer, Value: url},
		{Name: "CA name", Value: o.caName},
		{Name: "CA", Value: dn.Format(caCert.RawSubject)},
		{Name: fieldSHA256, Value: hex.EncodeToString(sum[:])},
		{Name: "Challenge", Value: challengeField},
		{Name: "Pending", Value: pending},
		{Name: fieldSaved, Value: o.caOut},
	}, nil)
	server := []string{"--" + flagServer, url}
	if o.caName != "" {
		server = append(server, "--"+flagCAName, shellQuote(o.caName))
	}
	caFile := o.caOut
	var lines []string
	if caFile == "" {
		caFile = "ca.pem"
		args := append([]string{programName, scepCommand, "cacert"}, server...)
		args = append(args, "--"+flagFingerprint, hex.EncodeToString(sum[:]), "--out", caFile)
		lines = append(lines, strings.Join(args, " "))
	}
	args := append([]string{programName, scepCommand, scepEnroll}, server...)
	args = append(args, "--"+flagCACert, shellQuote(caFile))
	if o.challengeFile != "" && o.challengeFile != stdoutPath {
		args = append(args, "--challenge-file", shellQuote(o.challengeFile))
	}
	args = append(args, enrollOutputs...)
	enroll := strings.Join(args, " ")
	switch {
	case o.anyChallenge:
		enroll = secret.ChallengeEnvVar + "=anything " + enroll
	case challenge.generated:
		enroll = secret.ChallengeEnvVar + "=" + string(challenge.value) + " " + enroll
	}
	lines = append(lines, enroll)
	p.line("\nEnroll a certificate from another terminal:\n  " + strings.Join(lines, "\n  ") +
		"\n\nPress Ctrl-C to stop.\n")
}

// scepMockLog prints one line for every request the test CA answers, with the reason of a refusal
// below it.
type scepMockLog struct {
	next http.Handler
	p    *printer
	// mu keeps the lines of concurrent requests apart.
	mu sync.Mutex
}

// ServeHTTP answers the request and prints what was asked and answered.
func (l *scepMockLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := io.ReadAll(io.LimitReader(r.Body, scepserver.DefaultMaxMessageBytes*2))
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	notes := &mockNotes{}
	r = r.WithContext(context.WithValue(r.Context(), mockNotesKey{}, notes))
	rec := &responseCapture{ResponseWriter: w, status: http.StatusOK}
	l.next.ServeHTTP(rec, r)

	req, _ := trace.SummarizeSCEPRequest(r, body)
	resp, _ := trace.SummarizeSCEPResponse(req.Operation,
		&http.Response{StatusCode: rec.status, Header: rec.Header()}, rec.body.Bytes())
	stamp := start.Format(time.TimeOnly)
	lines := []string{fmt.Sprintf("%s  %s  ->  %s  %s", stamp,
		describeSCEPRequest(req), describeSCEPResponse(rec.status, resp), formatRTT(time.Since(start)))}
	// The notes are indented to the column of the request, below the time.
	indent := strings.Repeat(" ", len(stamp)+2)
	for _, note := range notes.lines {
		lines = append(lines, indent+note)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range lines {
		l.p.line(line)
	}
}

// describeSCEPRequest names a request by its method, operation or message type and CA name.
func describeSCEPRequest(s *trace.SCEPSummary) string {
	parts := []string{s.Method, s.Label()}
	if s.CAName != "" {
		parts = append(parts, strconv.Quote(s.CAName))
	}
	if s.Digest != "" {
		parts = append(parts, s.Digest)
	}
	return ui.Sanitize(strings.Join(parts, "  "))
}

// describeSCEPResponse names a response by its status and content.
func describeSCEPResponse(status int, s *trace.SCEPSummary) string {
	parts := []string{fmt.Sprintf("HTTP %d", status)}
	switch {
	case s.Status != "":
		parts = append(parts, s.Label(), s.Status)
		if s.FailInfo != "" {
			parts = append(parts, s.FailInfo)
		}
	case len(s.Capabilities) > 0:
		parts = append(parts, count(len(s.Capabilities), "capability", "capabilities"))
	case s.Certificates > 0:
		parts = append(parts, count(s.Certificates, "certificate", "certificates"))
	}
	if s.Text != "" {
		parts = append(parts, strconv.Quote(ui.Sanitize(s.Text)))
	}
	return strings.Join(parts, "  ")
}

// scepMockNotes is a slog handler that turns the reasons the SCEP handler logs for a refusal, a
// deferral or an internal error into notes of the request log.
type scepMockNotes struct{}

// Enabled accepts every record.
func (scepMockNotes) Enabled(context.Context, slog.Level) bool { return true }

// Handle adds the reason of a record to the request log of ctx.
func (scepMockNotes) Handle(ctx context.Context, r slog.Record) error {
	var note string
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "cause", "error":
			note = a.Value.String()
		case "retry_after":
			note = "busy: the previous request was too recent"
		}
		return true
	})
	if note != "" {
		addMockNote(ctx, note)
	}
	return nil
}

// WithAttrs returns the handler, which keeps no attributes.
func (h scepMockNotes) WithAttrs([]slog.Attr) slog.Handler { return h }

// WithGroup returns the handler, which keeps no groups.
func (h scepMockNotes) WithGroup(string) slog.Handler { return h }
