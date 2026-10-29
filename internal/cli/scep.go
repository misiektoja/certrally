package cli

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 fingerprints identify CA certificates, as RFC 8894 section 2.2 allows.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pkcs7"
	"github.com/misiektoja/go-scep"
	"github.com/misiektoja/go-scep/scepclient"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/profile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// scepCommand is the name of the scep command group.
const scepCommand = "scep"

// scepExitStatusHelp lists the exit statuses of the SCEP commands that talk to a server.
const scepExitStatusHelp = "Exit status: 0 success, 1 usage or local error, " +
	"2 server unreachable or not speaking SCEP, 3 refused by the server, 4 protocol or verification failure, " +
	"6 a response broke the strict profile."

// newSCEPCommand returns the scep command group.
func newSCEPCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   scepCommand,
		Short: "Commands for the Simple Certificate Enrolment Protocol",
		Long: "Commands for the Simple Certificate Enrolment Protocol (SCEP, RFC 8894).\n\n" +
			"--server is the SCEP URL of the server, such as http://scep.example.com/scep. A server that serves " +
			"several CAs needs the name of the CA in --ca. SCEP signs and encrypts its messages, so it often runs " +
			"over plain HTTP. certrally then trusts the CA certificates of the first GetCACert answer, unless " +
			"--ca-cert names them or --fingerprint checks them.\n\n" +
			"The challenge password comes from --challenge, --challenge-file or the " + secret.ChallengeEnvVar +
			" environment variable. Other users of the machine can see --challenge in the process list.",
	}
	cmd.AddCommand(
		newSCEPCapsCommand(),
		newSCEPCACertCommand(),
		newSCEPChainCommand(),
		newSCEPNextCACommand(),
		newSCEPEnrollCommand(),
		newSCEPRenewCommand(),
		newSCEPPollCommand(),
		newSCEPGetCertCommand(),
		newSCEPGetCRLCommand(),
		newSCEPMockCommand(),
	)
	return cmd
}

// Flags of the SCEP connection.
const (
	flagCAName      = "ca"
	flagBusyRetries = "busy-retries"
	flagBusyWait    = "busy-wait"
	flagAllowDES    = "allow-des"
	// scepProxyHelp describes --proxy, which also takes SOCKS5 for SCEP.
	scepProxyHelp = "connect through this http, https or socks5 proxy instead of the one HTTP_PROXY or HTTPS_PROXY names"
	// scepHashHelp describes --hash. The default follows the digest choice of go-scep.
	scepHashHelp = "digest of the request signature: sha256, sha384, sha512, sha1 or md5, by default sha256, or sha512 " +
		"or sha1 when the server lists one of them and not SHA-256"
)

// scepConnection holds the flags that say how to reach a SCEP server.
type scepConnection struct {
	server string
	// caName is --ca, the message parameter that names the CA on a server with several.
	caName    string
	tlsCACert string
	insecure  bool
	proxy     string
	timeout   time.Duration
	capture   string
	profile   string
	// busyRetries and busyWait say how often and after how long a request answered with HTTP 503 is
	// sent again.
	busyRetries int
	busyWait    time.Duration
	// allowDES is --allow-des, which accepts answers encrypted with single DES.
	allowDES bool
}

// addFlags registers the connection flags with the given default timeout. Unless serverOptional is
// set, --server is required.
func (c *scepConnection) addFlags(cmd *cobra.Command, timeout time.Duration, timeoutHelp string, serverOptional bool) {
	f := cmd.Flags()
	f.StringVar(&c.server, flagServer, "",
		"address of the SCEP server, an http or https URL such as http://scep.example.com/scep")
	f.StringVar(&c.caName, flagCAName, "", "name of the CA, which a server with several CAs needs")
	f.StringVar(&c.tlsCACert, flagTLSCACert, "", "verify HTTPS with these CA certificates instead of the system roots")
	f.BoolVar(&c.insecure, flagInsecure, false, insecureHelp)
	f.StringVar(&c.proxy, flagProxy, "", scepProxyHelp)
	f.DurationVar(&c.timeout, flagTimeout, timeout, timeoutHelp)
	f.StringVar(&c.capture, "capture", "", "append the exchanged messages to this file as JSON Lines")
	f.StringVar(&c.profile, "profile", profile.Compatible,
		"how to treat responses that break RFC 8894: compatible warns, strict fails")
	f.IntVar(&c.busyRetries, flagBusyRetries, 3,
		"how often to send a request again after the server answers HTTP 503, 0 for never")
	f.DurationVar(&c.busyWait, flagBusyWait, 5*time.Second,
		"wait before sending a request again after HTTP 503 without a Retry-After header")
	if !serverOptional {
		_ = cmd.MarkFlagRequired(flagServer)
	}
	cmd.MarkFlagsMutuallyExclusive(flagTLSCACert, flagInsecure)
	_ = cmd.RegisterFlagCompletionFunc("profile", fixedCompletion(profile.Names))
	for _, name := range []string{flagServer, flagCAName, flagTimeout, flagProxy, flagBusyRetries, flagBusyWait} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// addDecryptFlags registers --allow-des on the commands that decrypt a certificate or CRL.
func (c *scepConnection) addDecryptFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&c.allowDES, flagAllowDES, false,
		"accept answers encrypted with single DES, which some servers send whatever the request used")
}

// validate checks the server URL, the timeout, the profile, the proxy and the busy retries.
func (c *scepConnection) validate() error {
	if err := checkSCEPServer(c.server); err != nil {
		return err
	}
	switch {
	case c.timeout <= 0:
		return errors.New("--timeout must be positive")
	case c.busyRetries < 0:
		return fmt.Errorf("--%s must not be negative", flagBusyRetries)
	case c.busyWait <= 0:
		return fmt.Errorf("--%s must be positive", flagBusyWait)
	}
	if !slices.Contains(profile.Names, c.profile) {
		return fmt.Errorf("invalid --profile %q, want compatible or strict", c.profile)
	}
	_, err := parseSCEPProxy(c.proxy)
	return err
}

// checkCapture rejects a --capture file that is also an output of the command.
func (c *scepConnection) checkCapture(outputs ...string) error {
	return (&connection{capture: c.capture}).checkCapture(outputs...)
}

// checkSCEPServer checks a --server URL: http or https with a host, and without the query that
// certrally fills in.
func checkSCEPServer(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("--server %q is not an http or https URL", s)
	}
	if u.User != nil {
		return errors.New("--server must not hold a username or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("--server %q has a query or fragment. Leave them out, certrally adds the operation", s)
	}
	return nil
}

// parseSCEPProxy returns the --proxy URL, or nil when the flag is empty. It accepts SOCKS5 proxies
// besides HTTP and HTTPS ones.
func parseSCEPProxy(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || !slices.Contains([]string{schemeHTTP, schemeHTTPS, "socks5", "socks5h"}, u.Scheme) {
		return nil, fmt.Errorf("--proxy %q is not an http, https or socks5 URL", s)
	}
	return u, nil
}

// scepTrust holds the flags that say which CA certificates to trust.
type scepTrust struct {
	caCerts     []string
	fingerprint string
}

// Flags that name the trusted CA certificates.
const (
	flagCACert      = "ca-cert"
	flagFingerprint = "fingerprint"
)

// addFlags registers --ca-cert and --fingerprint.
func (t *scepTrust) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArrayVar(&t.caCerts, flagCACert, nil,
		"use these CA and RA certificates instead of asking the server for them (repeatable)")
	f.StringVar(&t.fingerprint, flagFingerprint, "",
		"hex SHA-256 or SHA-1 fingerprint of the CA certificate, which the certificates from the server must have")
	cmd.MarkFlagsMutuallyExclusive(flagCACert, flagFingerprint)
	_ = cmd.RegisterFlagCompletionFunc(flagFingerprint, cobra.NoFileCompletions)
}

// fingerprintBytes decodes --fingerprint. It returns nil without the flag.
func (t *scepTrust) fingerprintBytes() ([]byte, error) {
	if t.fingerprint == "" {
		return nil, nil
	}
	return parseSCEPFingerprint(t.fingerprint)
}

// parseSCEPFingerprint decodes a SHA-256 or SHA-1 fingerprint written as hex, with optional colons
// or spaces. SCEP CAs often publish SHA-1 fingerprints (RFC 8894 section 2.2).
func parseSCEPFingerprint(s string) ([]byte, error) {
	compact := strings.NewReplacer(":", "", " ", "").Replace(s)
	fp, err := hex.DecodeString(compact)
	if err != nil || (len(fp) != sha256.Size && len(fp) != sha1.Size) {
		return nil, fmt.Errorf("--fingerprint %q is not a SHA-256 or SHA-1 fingerprint of 64 or 40 hex digits", s)
	}
	return fp, nil
}

// matchSCEPFingerprint returns the certificate whose SHA-256 or SHA-1 fingerprint, as the length
// of fp says, is fp. It returns nil when none is.
func matchSCEPFingerprint(certs []*x509.Certificate, fp []byte) *x509.Certificate {
	if len(fp) == sha256.Size {
		return matchFingerprint(certs, fp)
	}
	for _, cert := range certs {
		if sum := sha1.Sum(cert.Raw); bytes.Equal(sum[:], fp) { //nolint:gosec // G401: see the import.
			return cert
		}
	}
	return nil
}

// loadPinned reads the --ca-cert certificates. It returns nil without the flag.
func (t *scepTrust) loadPinned() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, path := range t.caCerts {
		read, err := pemfile.ReadCertificates(path)
		if err != nil {
			return nil, err
		}
		certs = append(certs, read...)
	}
	return certs, nil
}

// scepSession is an open SCEP client that records every exchange.
type scepSession struct {
	*recording
	conn   *scepConnection
	client *scepclient.Client
	// plainHTTP is set for an http server, which nothing authenticates.
	plainHTTP bool
	// pinned is set when --ca-cert or a state file named the CA certificates.
	pinned bool
	// ca holds the trusted CA certificates once the session has them.
	ca *scepclient.CACertificates
}

// open prepares a session and registers it with p.
func (c *scepConnection) open(p *printer) (*scepSession, error) {
	rec, err := openRecording(p, recordingOptions{
		server:   c.server,
		profile:  c.profile,
		capture:  c.capture,
		protocol: trace.SCEP,
		insecure: c.insecure,
	})
	if err != nil {
		return nil, err
	}
	var roots []*x509.Certificate
	if c.tlsCACert != "" {
		if roots, err = pemfile.ReadCertificates(c.tlsCACert); err != nil {
			return nil, err
		}
	}
	proxy, err := parseSCEPProxy(c.proxy)
	if err != nil {
		return nil, err
	}
	rec.recorder.Next = newTransport(roots, c.insecure, proxy)
	s := &scepSession{
		recording: rec,
		conn:      c,
		plainHTTP: strings.HasPrefix(strings.ToLower(c.server), schemeHTTP+"://"),
	}
	retries := c.busyRetries
	if retries == 0 {
		// go-scep reads zero as its default and a negative count as never.
		retries = -1
	}
	var decrypt pkcs7.DecryptOptions
	if c.allowDES {
		decrypt.ContentEncryptionAlgorithms = append(slices.Clone(pkcs7.DefaultContentDecryptionAlgorithms), pkcs7.DESCBC)
	}
	s.client, err = scepclient.New(c.server, scepclient.Options{
		HTTPClient:  &http.Client{Transport: rec.recorder},
		CAName:      c.caName,
		BusyRetries: retries,
		BusyDelay:   c.busyWait,
		Decrypt:     decrypt,
		OnBusy:      s.onBusy,
	})
	if err != nil {
		return nil, err
	}
	rec.recorder.Inspect = s.inspect
	return s, nil
}

// onBusy notes in the ladder that the server answered HTTP 503 and the request goes again.
func (s *scepSession) onBusy(_ *scepclient.HTTPError, delay time.Duration) {
	if s.ladder != nil {
		s.ladder.Note(fmt.Sprintf("server busy, sending again in %s", delay))
	}
}

// inspect checks a response against the profile. A strict session stops a response that breaks a
// rule before the client accepts it. A FAILURE answer is not stopped, because its reason matters
// more.
func (s *scepSession) inspect(_, response trace.Event) error {
	findings := profile.CheckSCEP(scepResponse(response.Record(true)))
	return s.report(findings, response.SCEP.Status != trace.SCEPFailure)
}

// scepResponse returns what the SCEP rules check in a recorded response.
func scepResponse(rec trace.Record) profile.SCEPResponse {
	return profile.SCEPResponse{
		Operation:    rec.Operation,
		HTTPStatus:   rec.HTTPStatus,
		ContentType:  rec.ContentType,
		Body:         rec.DER,
		Certificates: rec.Certificates,
		MessageType:  rec.MessageType,
		SenderNonce:  rec.SenderNonce != "",
	}
}

// run performs op against the server and draws the ladder around it. A failure is reported before
// the error is returned.
func (s *scepSession) run(ctx context.Context, op func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.conn.timeout)
	defer cancel()
	s.startLadder()
	err := op(ctx)
	s.endLadder()
	if err != nil {
		return s.fail(err)
	}
	return nil
}

// scepRun opens a session and runs op. A failure is reported before the error is returned.
func scepRun[T any](ctx context.Context, conn *scepConnection, p *printer, op func(context.Context, *scepSession) (T, error)) (T, *scepSession, error) {
	var zero T
	s, err := conn.open(p)
	if err != nil {
		return zero, nil, err
	}
	var result T
	err = s.run(ctx, func(ctx context.Context) error {
		var opErr error
		result, opErr = op(ctx, s)
		return opErr
	})
	if err != nil {
		return zero, s, err
	}
	return result, s, nil
}

// plainHTTPSCEPWarning is the warning of a session that trusted the GetCACert answer over plain HTTP.
const plainHTTPSCEPWarning = "The CA certificates were trusted from the GetCACert answer over plain HTTP, " +
	"which nothing authenticates. Check a fingerprint with --fingerprint or name them with --ca-cert " +
	"unless you trust the network."

// caCertificates returns the CA certificates the session trusts: the pinned ones, or else those of a
// GetCACert answer, checked against fp when it is set. Trusted certificates that nothing checked are
// reported with their fingerprints.
func (s *scepSession) caCertificates(ctx context.Context, pinned []*x509.Certificate, fp []byte) (*scepclient.CACertificates, error) {
	if s.ca != nil {
		return s.ca, nil
	}
	if len(pinned) > 0 {
		ca, err := scepclient.SortCACertificates(pinned)
		if err != nil {
			return nil, &scepTrustError{err: err}
		}
		s.ca, s.pinned = ca, true
		return ca, nil
	}
	got, err := s.client.GetCACert(ctx)
	if err != nil {
		return nil, err
	}
	certs := got.All
	if fp != nil {
		matched := matchSCEPFingerprint(certs, fp)
		if matched == nil {
			return nil, &scepTrustError{err: fmt.Errorf("none of the %s has the fingerprint %x",
				count(len(certs), "certificate", "certificates"), fp)}
		}
		covered, rest := coveredBy(certs, matched)
		for _, cert := range rest {
			s.warnAfterLadder(ui.Sanitize(dn.Format(cert.RawSubject)) + " is not trusted: it neither has the checked " +
				"fingerprint nor was issued by the certificate that has it.")
		}
		if got, err = scepclient.SortCACertificates(covered); err != nil {
			return nil, &scepTrustError{err: err}
		}
	} else {
		s.p.trustedOnFirstResponse(certs)
		if s.plainHTTP {
			s.warnAfterLadder(plainHTTPSCEPWarning)
		}
	}
	s.ca = got
	return got, nil
}

// scepTrustError reports CA certificates that cannot be trusted or used.
type scepTrustError struct{ err error }

// Error describes the problem.
func (e *scepTrustError) Error() string { return e.err.Error() }

// Unwrap returns the cause.
func (e *scepTrustError) Unwrap() error { return e.err }

// scepFailureError is a FAILURE answer to an enrollment or a poll.
type scepFailureError struct {
	failInfo string
}

// Error names the failure reason.
func (e *scepFailureError) Error() string {
	return "the CA answered FAILURE with " + e.failInfo
}

// scepExitCode classifies a failed SCEP exchange.
func scepExitCode(err error, r *trace.Recorder) int {
	_, violation := errors.AsType[*profileError](err)
	_, refused := errors.AsType[*scepclient.HTTPError](err)
	_, failed := errors.AsType[*scepclient.FailureError](err)
	_, rejected := errors.AsType[*scepFailureError](err)
	switch {
	case violation:
		return exitProfile
	case errors.Is(err, context.Canceled):
		return exitLocal
	case r.TransportError() != nil, errors.Is(err, context.DeadlineExceeded):
		return exitTransport
	case refused, failed, rejected:
		return exitRejected
	case len(r.Events()) == 0:
		return exitLocal
	}
	return exitProtocol
}

// fail explains a failed exchange and returns the error that carries the exit status.
func (s *scepSession) fail(err error) error {
	return s.p.fail(s.failure(err), err)
}

// failure describes a failed exchange.
func (s *scepSession) failure(err error) *failure {
	code := scepExitCode(err, s.recorder)
	switch code {
	case exitRejected:
		return s.refusal(err)
	case exitTransport:
		problem := s.recorder.TransportError()
		if problem == nil {
			problem = err
		}
		return &failure{
			code:    code,
			Title:   "No SCEP answer from the server",
			Message: problem.Error(),
			Hint:    s.transportHint(err, problem),
		}
	case exitLocal:
		return &failure{code: code, Title: titleNotCompleted, Message: err.Error()}
	case exitProfile:
		return profileFailure(err)
	}
	f := &failure{code: code, Title: titleExchangeFailed, Message: err.Error()}
	if errors.Is(err, pkcs7.ErrContentEncryptionNotAllowed) {
		f.Title = "The answer uses a cipher certrally does not accept"
		f.Hint = "The server encrypted its answer with a weak cipher that certrally refuses by default."
		if !s.conn.allowDES && strings.HasSuffix(err.Error(), pkcs7.DESCBC.String()) {
			f.Hint = "The server encrypted its answer with single DES whatever the request used. Add --" + flagAllowDES +
				" to accept it."
		}
	} else if _, ok := errors.AsType[*scepTrustError](err); ok {
		f.Title = "The CA certificates cannot be trusted"
		f.Hint = hintCheckFingerprint
		if s.pinned {
			f.Hint = "Check the certificates in --ca-cert."
		}
	} else if strings.Contains(err.Error(), "verify") && !s.pinned {
		f.Hint = "The answer is not signed by the CA certificates from GetCACert. The server may sign with " +
			"another certificate. Pass it with --ca-cert."
	}
	return f
}

// refusal describes an HTTP error status or a FAILURE answer.
func (s *scepSession) refusal(err error) *failure {
	if httpErr, ok := errors.AsType[*scepclient.HTTPError](err); ok {
		f := &failure{
			code:       exitRejected,
			Title:      "The SCEP server refused the request",
			Message:    err.Error(),
			HTTPStatus: httpErr.StatusCode,
			Hint:       scepRefusalHint(httpErr.StatusCode, s.conn),
		}
		if events := s.recorder.Events(); len(events) > 0 {
			if e := events[len(events)-1].SCEP; e != nil {
				if e.Text != "" {
					f.StatusText = []string{e.Text}
				}
				f.RetryAfter = e.RetryAfter
			}
		}
		return f
	}
	info := ""
	if failErr, ok := errors.AsType[*scepclient.FailureError](err); ok && failErr.Status == scep.FAILURE {
		info = trace.SCEPFailInfoName(string(failErr.FailInfo))
	}
	if failErr, ok := errors.AsType[*scepFailureError](err); ok {
		info = failErr.failInfo
	}
	f := &failure{
		code:    exitRejected,
		Title:   "The CA rejected the request",
		Message: err.Error(),
		Status:  trace.SCEPFailure,
	}
	if info != "" {
		f.FailInfo = []string{info}
	}
	f.Hint = scepFailInfoHints[info]
	return f
}

// scepFailInfoHints suggests what to change for each failInfo of RFC 8894 section 3.2.1.4.
var scepFailInfoHints = map[string]string{
	"badAlg":          "The CA does not accept the algorithms of the request. Try another --hash or --cipher.",
	"badMessageCheck": "The CA could not verify the request signature. Try another --hash.",
	"badRequest":      "The CA did not accept the request. Check the challenge password, --subject and --san.",
	"badTime":         "The CA rejected the message time. Check the system clock.",
	"badCertId":       "The CA does not know this certificate. Check --serial and --ca.",
}

// scepRefusalHint suggests what to change for an HTTP error status. It returns "" when it has
// nothing.
func scepRefusalHint(status int, c *scepConnection) string {
	switch status {
	case http.StatusBadRequest:
		if c.caName == "" {
			return "The server did not accept the request. It may need the name of the CA in --ca."
		}
		return "The server did not accept the request. Check the name of the CA in --ca."
	case http.StatusForbidden:
		return "The server does not allow this request."
	case http.StatusRequestEntityTooLarge:
		return "The request is larger than the server accepts."
	case http.StatusServiceUnavailable:
		return fmt.Sprintf("The server is busy or limits how often a client may send requests. "+
			"Run the command again later, or raise --%s and --%s.", flagBusyRetries, flagBusyWait)
	case http.StatusNotImplemented:
		return "The server does not offer this operation."
	}
	return ""
}

// lastMessageType returns the message type of the last request, which is "" unless it was a PKIOperation.
func (s *scepSession) lastMessageType() string {
	for _, ev := range slices.Backward(s.recorder.Events()) {
		if ev.Kind == trace.Request && ev.SCEP != nil {
			return ev.SCEP.MessageType
		}
	}
	return ""
}

// transportHint suggests a fix for a failure to get a SCEP answer. It returns "" when it has none.
func (s *scepSession) transportHint(err, problem error) string {
	if strings.HasSuffix(problem.Error(), "with an empty body") {
		// Some servers answer a message type they do not support without content.
		switch t := s.lastMessageType(); t {
		case "RenewalReq", "GetCert", "GetCRL":
			return "The server answered without content. It may not support " + t + "."
		}
		if s.conn.caName == "" {
			return "The server answered without content. It may need the name of the CA in --ca."
		}
		return "The server answered without content. Check the name of the CA in --ca."
	}
	// A server answers 404 for a wrong path and often for a CA name it does not serve.
	if strings.HasPrefix(problem.Error(), "HTTP 404") {
		if s.conn.caName == "" {
			return "Check the path in --server. A server with several CAs also needs the name of the CA in --ca."
		}
		return "Check the path in --server and the name of the CA in --ca."
	}
	return transportHint(err, problem, s.conn.timeout)
}

// readChallenge returns the challenge password from --challenge, --challenge-file or the
// environment, or "" when none is given. It never prompts, because many enrollments need none.
func readChallenge(value secret.Value, file string, stdin io.Reader) (string, error) {
	src := secret.Source{Kind: secret.Challenge, Value: value.Bytes(), File: file, LookupEnv: os.LookupEnv}
	if file == stdoutPath {
		src.Stdin = stdin
	}
	challenge, err := src.Read()
	if errors.Is(err, secret.ErrMissing) {
		return "", nil
	}
	return string(challenge), err
}
