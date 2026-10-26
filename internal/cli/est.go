package cli

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	est "github.com/misiektoja/go-pki-est"
	srptls "github.com/misiektoja/go-tls-srp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/profile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// estCommand is the name of the est command group.
const estCommand = "est"

// estPath is the path prefix of EST (RFC 7030 section 3.2.2).
const estPath = "/.well-known/est"

// estOperations are the EST operations, which cannot be a CA label.
var estOperations = []string{"cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs"}

// estExitStatusHelp lists the exit statuses of the EST commands that talk to a server.
const estExitStatusHelp = "Exit status: 0 success, 1 usage or local error, 2 server unreachable or not speaking EST, " +
	"3 refused by the server, 4 protocol or verification failure, 6 a response broke the strict profile."

// newESTCommand returns the est command group.
func newESTCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   estCommand,
		Short: "Commands for Enrollment over Secure Transport",
		Long: "Commands for Enrollment over Secure Transport (EST, RFC 7030).\n\n" +
			"EST runs over HTTPS. --server is the address of the server, such as https://est.example.com. " +
			"To choose a CA on a server that offers several, add /.well-known/est/LABEL.\n\n" +
			"A client signs in with a TLS client certificate (--cert and --key), with a password (--user) over " +
			"HTTP Basic authentication, with a bearer token (--token) or with a certificate and a password or " +
			"token. With --srp, --user signs in with TLS-SRP (RFC 7030 section 3.3.3) instead, which also " +
			"authenticates the server without a certificate. The password and the token are read from " +
			"--password-file or --token-file, the " + secret.PasswordEnvVar + " or " + secret.TokenEnvVar +
			" environment variable or a prompt, never from the command line.",
	}
	cmd.AddCommand(
		newESTCACertsCommand(),
		newESTCSRAttrsCommand(),
		newESTEnrollCommand(),
		newESTReenrollCommand(),
		newESTServerKeyGenCommand(),
		newESTMockCommand(),
	)
	return cmd
}

// estConnection holds the flags that say how to reach an EST server and how to trust it.
type estConnection struct {
	server    string
	tlsCACert string
	timeout   time.Duration
	capture   string
	profile   string
	// insecure is the --insecure flag. It skips the check of the server certificate and is reported
	// as a warning.
	insecure bool
	// unverified also skips the check, for est cacerts --bootstrap, which reports the missing check
	// in its result instead.
	unverified bool
	// proxy is the --proxy URL, which replaces the proxy from the environment.
	proxy string
}

// addFlags registers the connection flags with the given default timeout.
func (c *estConnection) addFlags(cmd *cobra.Command, timeout time.Duration, timeoutHelp string) {
	f := cmd.Flags()
	f.StringVar(&c.server, flagServer, "",
		"address of the EST server, an https URL that may end in "+estPath+"/LABEL to choose a CA")
	f.StringVar(&c.tlsCACert, flagTLSCACert, "",
		"verify the server with these CA certificates instead of the system roots")
	f.BoolVar(&c.insecure, flagInsecure, false, insecureHelp)
	f.StringVar(&c.proxy, flagProxy, "", proxyHelp)
	f.DurationVar(&c.timeout, "timeout", timeout, timeoutHelp)
	f.StringVar(&c.capture, "capture", "", "append the exchanged messages to this file as JSON Lines")
	f.StringVar(&c.profile, "profile", profile.Compatible,
		"how to treat responses that break RFC 7030: compatible warns, strict fails")
	_ = cmd.MarkFlagRequired(flagServer)
	cmd.MarkFlagsMutuallyExclusive(flagTLSCACert, flagInsecure)
	_ = cmd.RegisterFlagCompletionFunc("profile", fixedCompletion(profile.Names))
	for _, name := range []string{flagServer, "timeout", flagProxy} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// validate checks the server URL, the timeout, the profile and the proxy.
func (c *estConnection) validate() error {
	if _, err := parseESTServer(c.server); err != nil {
		return err
	}
	if c.timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	if !slices.Contains(profile.Names, c.profile) {
		return fmt.Errorf("invalid --profile %q, want compatible or strict", c.profile)
	}
	if _, err := parseProxy(c.proxy); err != nil {
		return err
	}
	return nil
}

// checkCapture rejects a --capture file that is also an output of the command.
func (c *estConnection) checkCapture(outputs ...string) error {
	return (&connection{capture: c.capture}).checkCapture(outputs...)
}

// estServer is the address of an EST server.
type estServer struct {
	// host is the host and port to connect to.
	host string
	// label is the CA label of the path, if any.
	label string
}

// parseESTServer parses a --server URL: https, a host, an optional port and an optional path of
// /.well-known/est with a CA label.
func parseESTServer(s string) (estServer, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.Opaque != "" {
		return estServer{}, fmt.Errorf("--server %q is not an https URL. EST runs over HTTPS", s)
	}
	if u.User != nil {
		return estServer{}, errors.New("--server must not hold a username or password. Use --user")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return estServer{}, fmt.Errorf("--server %q has a query or fragment, which EST does not use", s)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	srv := estServer{host: host}
	path := strings.TrimSuffix(u.Path, "/")
	if path == "" || path == estPath {
		return srv, nil
	}
	label, ok := strings.CutPrefix(path, estPath+"/")
	if !ok || label == "" || strings.Contains(label, "/") {
		return estServer{}, fmt.Errorf("--server path %q is not %s or %s/LABEL", u.Path, estPath, estPath)
	}
	if slices.Contains(estOperations, label) {
		return estServer{}, fmt.Errorf("--server ends in the operation %q. Leave it out, certrally adds it", label)
	}
	srv.label = label
	return srv, nil
}

// estAuth holds the flags that sign in to an EST server.
type estAuth struct {
	user         string
	passwordFile string
	certFile     string
	keyFile      string
	keyPassword
	// srp signs in with TLS-SRP instead of HTTP Basic authentication.
	srp bool
	// token signs in with a bearer token instead of a password. tokenFile names its file and implies
	// token.
	token     bool
	tokenFile string
}

// addFlags registers the sign-in flags. certHelp describes --cert. Unless certAlone is set, --cert
// needs --key. The connection flags must be registered first.
func (a *estAuth) addFlags(cmd *cobra.Command, certHelp string, certAlone bool) {
	f := cmd.Flags()
	f.StringVar(&a.user, "user", "", "username for HTTP Basic authentication, or for TLS-SRP with --srp")
	f.StringVar(&a.passwordFile, "password-file", "", "read the password from a file, or - for standard input")
	f.StringVar(&a.certFile, "cert", "", certHelp)
	f.StringVar(&a.keyFile, "key", "", "private key for --cert, to sign in with a TLS client certificate")
	a.keyPassword.addFlags(cmd)
	f.BoolVar(&a.srp, "srp", false,
		"sign in as --user with TLS-SRP, which also authenticates the server, instead of HTTP Basic authentication")
	f.BoolVar(&a.token, flagToken, false, "sign in with a bearer token over HTTP Bearer authentication instead of --user")
	f.StringVar(&a.tokenFile, flagTokenFile, "",
		"read the bearer token from a file, or - for standard input, which implies --token")
	if !certAlone {
		cmd.MarkFlagsRequiredTogether("cert", "key")
	}
	// TLS-SRP authenticates the server with the password, so it has no certificate to check.
	cmd.MarkFlagsMutuallyExclusive("srp", flagTLSCACert)
	cmd.MarkFlagsMutuallyExclusive("srp", flagInsecure)
	// A request carries one Authorization header, so a token and a password cannot both sign in.
	cmd.MarkFlagsMutuallyExclusive(flagToken, "user")
	cmd.MarkFlagsMutuallyExclusive(flagTokenFile, "user")
	cmd.MarkFlagsMutuallyExclusive(flagTokenFile, "password-file")
	_ = cmd.RegisterFlagCompletionFunc("user", cobra.NoFileCompletions)
}

// Flags of the bearer token sign-in.
const (
	flagToken     = "token"
	flagTokenFile = "token-file"
)

// validate checks flags that only make sense together.
func (a *estAuth) validate() error {
	switch {
	case a.passwordFile != "" && a.user == "":
		return errors.New("--password-file needs --user")
	case a.keyFile != "" && a.certFile == "":
		return errors.New("--key needs --cert")
	case a.srp && a.user == "":
		return errors.New("--srp needs --user")
	case a.srp && a.keyFile != "":
		return errors.New("--srp signs in without a TLS client certificate. Leave out --key")
	}
	if err := a.checkStdin("--password-file", a.passwordFile); err != nil {
		return err
	}
	return a.checkStdin("--token-file", a.tokenFile)
}

// estCredentials are the loaded sign-in credentials.
type estCredentials struct {
	user     string
	password string
	// token signs in with HTTP Bearer authentication instead of user and password.
	token string
	// srp signs in as user with TLS-SRP instead of HTTP Basic authentication.
	srp bool
	// chain is the --cert certificate followed by its chain. key signs in with it, when set.
	chain []*x509.Certificate
	key   crypto.Signer
}

// load reads the credentials. The password may be prompted for on stdin.
func (a *estAuth) load(stdin io.Reader, prompt io.Writer) (*estCredentials, error) {
	creds := &estCredentials{user: a.user, srp: a.srp}
	if a.user != "" {
		password, err := secret.Source{
			Kind:      secret.Password,
			File:      a.passwordFile,
			LookupEnv: os.LookupEnv,
			Stdin:     stdin,
			Prompt:    prompt,
		}.Read()
		if err != nil {
			return nil, err
		}
		creds.password = string(password)
	}
	if a.token || a.tokenFile != "" {
		token, err := secret.Source{
			Kind:      secret.Token,
			File:      a.tokenFile,
			LookupEnv: os.LookupEnv,
			Stdin:     stdin,
			Prompt:    prompt,
		}.Read()
		if err != nil {
			return nil, err
		}
		creds.token = string(token)
	}
	if a.certFile != "" {
		chain, err := pemfile.ReadCertificates(a.certFile)
		if err != nil {
			return nil, err
		}
		creds.chain = chain
	}
	if a.keyFile != "" {
		key, err := a.keyPassword.load(a.keyFile, stdin, prompt)
		if err != nil {
			return nil, err
		}
		if _, composite := key.(*compositemldsa.PrivateKey); composite {
			return nil, errors.New("TLS cannot sign in with a composite ML-DSA key. Use --user instead")
		}
		creds.key = key
	}
	return creds, nil
}

// estSession is an open EST client that records every exchange.
type estSession struct {
	*recording
	conn   *estConnection
	creds  *estCredentials
	client *est.Client
}

// open prepares a session and registers it with p.
func (c *estConnection) open(p *printer, creds *estCredentials) (*estSession, error) {
	srv, err := parseESTServer(c.server)
	if err != nil {
		return nil, err
	}
	rec, err := openRecording(p, recordingOptions{
		server:   c.server,
		profile:  c.profile,
		capture:  c.capture,
		protocol: trace.EST,
		insecure: c.insecure,
	})
	if err != nil {
		return nil, err
	}
	s := &estSession{recording: rec, conn: c, creds: creds}
	s.client = &est.Client{
		Host:                  srv.host,
		AdditionalPathSegment: srv.label,
		// G402: --insecure is reported as a warning and est cacerts --bootstrap shows the fingerprints
		// for an out-of-band check.
		InsecureSkipVerify: c.insecure || c.unverified, //nolint:gosec
		// The profile reports a chain in an enrollment response, so the client must accept it.
		AllowCertificateChain: true,
		WrapTransport:         rec.recorder.Wrap,
		OnConnect: func(conn net.Conn) {
			switch tc := conn.(type) {
			case *tls.Conn:
				rec.recorder.Connected(trace.TLSInfoFromState(tc.ConnectionState()))
			case *srptls.Conn:
				cs := tc.ConnectionState()
				rec.recorder.Connected(trace.TLSInfo{
					Version:     tls.VersionName(cs.Version),
					CipherSuite: srptls.CipherSuiteName(cs.CipherSuite),
					SRPUser:     cs.SRPUsername,
				})
			}
		},
	}
	if c.tlsCACert != "" {
		certs, err := pemfile.ReadCertificates(c.tlsCACert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		s.client.ExplicitAnchor = pool
	}
	proxy, err := parseProxy(c.proxy)
	if err != nil {
		return nil, err
	}
	if proxy != nil {
		s.client.Proxy = http.ProxyURL(proxy)
	}
	switch {
	case creds.srp:
		s.client.SRPUsername, s.client.SRPPassword = creds.user, creds.password
	case creds.token != "":
		s.client.BearerToken = creds.token
	case creds.user != "":
		s.client.Username, s.client.Password = creds.user, creds.password
	}
	if creds.key != nil {
		s.client.Certificates, s.client.PrivateKey = creds.chain, creds.key
	}
	rec.recorder.Inspect = s.inspect
	return s, nil
}

// inspect checks a response against the profile. A strict session stops a response that breaks a
// rule before the client accepts it.
func (s *estSession) inspect(_, response trace.Event) error {
	return s.report(profile.CheckEST(estResponse(response.Record(false))), true)
}

// estResponse returns what the EST rules check in a recorded response. The certificate part of a
// serverkeygen response stands for the response.
func estResponse(rec trace.Record) profile.ESTResponse {
	r := profile.ESTResponse{
		Operation:    rec.Operation,
		HTTPStatus:   rec.HTTPStatus,
		ContentType:  rec.ContentType,
		RetryAfter:   rec.RetryAfter != nil,
		Certificates: rec.Certificates,
	}
	if rec.Content == trace.ContentServerKeyGen {
		r.ContentType = ""
		for _, part := range rec.Parts {
			if isCertsPart(part.ContentType) {
				r.ContentType = part.ContentType
				break
			}
		}
	}
	return r
}

// isCertsPart reports whether a part of a serverkeygen response holds the certificate.
func isCertsPart(contentType string) bool {
	mediaType, params, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/pkcs7-mime" && params["smime-type"] != "server-generated-key"
}

// Waits when the server answers 202 Accepted without a usable Retry-After value.
const (
	defaultRetryWait = 10 * time.Second
	minRetryWait     = time.Second
)

// retryTimeout reports a wait the server asked for that does not fit in the timeout.
type retryTimeout struct {
	wait    time.Duration
	timeout time.Duration
}

// Error says how long the server asked to wait.
func (e *retryTimeout) Error() string {
	return fmt.Sprintf("the server asked to retry after %s, which is beyond --timeout %s", e.wait, e.timeout)
}

// run performs op against the server and draws the ladder around it. With retry set, a 202
// Accepted answer makes it wait as the server asks and send the request again, within the timeout.
// A failure is reported before the error is returned.
func (s *estSession) run(ctx context.Context, retry bool, op func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.conn.timeout)
	defer cancel()
	s.startLadder()
	err := s.attempts(ctx, retry, op)
	s.endLadder()
	if err != nil {
		return s.fail(err)
	}
	return nil
}

// attempts runs op until it succeeds, fails or, with retry set, stops answering 202 Accepted.
func (s *estSession) attempts(ctx context.Context, retry bool, op func(context.Context) error) error {
	for {
		start, sent := time.Now(), len(s.recorder.Events())
		err := op(ctx)
		if err == nil {
			return nil
		}
		s.recordConnectFailure(err, sent, time.Since(start))
		estErr, ok := errors.AsType[est.Error](err)
		if !retry || !ok || estErr.StatusCode() != http.StatusAccepted {
			return err
		}
		wait := defaultRetryWait
		if events := s.recorder.Events(); len(events) > 0 && events[len(events)-1].EST != nil &&
			events[len(events)-1].EST.RetryAfter != nil {
			wait = max(time.Duration(*events[len(events)-1].EST.RetryAfter)*time.Second, minRetryWait)
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
			return &retryTimeout{wait: wait, timeout: s.conn.timeout}
		}
		if s.ladder != nil {
			s.ladder.Note(fmt.Sprintf("waiting %s as the server asked", wait))
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// recordConnectFailure records an error that stopped op before it sent a request, such as a TLS
// handshake failure, so that the ladder, the capture and the exit status show it.
func (s *estSession) recordConnectFailure(err error, sent int, elapsed time.Duration) {
	for _, ev := range s.recorder.Events()[sent:] {
		if ev.Kind == trace.Request {
			return
		}
	}
	if isConnectError(err) {
		s.recorder.Failed(err, elapsed)
	}
}

// isConnectError reports whether err comes from connecting to the server.
func isConnectError(err error) bool {
	_, opErr := errors.AsType[*net.OpError](err)
	_, dnsErr := errors.AsType[*net.DNSError](err)
	_, verifyErr := errors.AsType[*tls.CertificateVerificationError](err)
	_, record := errors.AsType[tls.RecordHeaderError](err)
	_, unknownAuthority := errors.AsType[x509.UnknownAuthorityError](err)
	_, wrongHost := errors.AsType[x509.HostnameError](err)
	_, invalid := errors.AsType[x509.CertificateInvalidError](err)
	return opErr || dnsErr || verifyErr || record || unknownAuthority || wrongHost || invalid ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, context.DeadlineExceeded)
}

// estExitCode classifies a failed EST exchange.
func estExitCode(err error, r *trace.Recorder) int {
	_, violation := errors.AsType[*profileError](err)
	_, refused := errors.AsType[est.Error](err)
	_, waited := errors.AsType[*retryTimeout](err)
	switch {
	case violation:
		return exitProfile
	case errors.Is(err, context.Canceled):
		return exitLocal
	case isSRPRefusal(err):
		return exitRejected
	case waited, r.TransportError() != nil, errors.Is(err, context.DeadlineExceeded):
		return exitTransport
	case refused:
		return exitRejected
	case len(r.Events()) == 0:
		return exitLocal
	}
	return exitProtocol
}

// fail explains a failed exchange and returns the error that carries the exit status.
func (s *estSession) fail(err error) error {
	return s.p.fail(s.failure(err), err)
}

// failure describes a failed exchange.
func (s *estSession) failure(err error) *failure {
	code := estExitCode(err, s.recorder)
	switch code {
	case exitRejected:
		if isSRPRefusal(err) {
			return srpRefusal(err)
		}
		return s.refusal(err)
	case exitTransport:
		problem := s.recorder.TransportError()
		if problem == nil {
			problem = err
		}
		return &failure{
			code:    code,
			Title:   "No EST answer from the server",
			Message: problem.Error(),
			Hint:    s.transportHint(err, problem),
		}
	case exitLocal:
		return &failure{code: code, Title: "The request was not completed", Message: err.Error()}
	case exitProfile:
		return profileFailure(err)
	default:
		return &failure{code: code, Title: "The exchange failed", Message: err.Error()}
	}
}

// profileFailure describes a response that breaks the strict profile.
func profileFailure(err error) *failure {
	violation, _ := errors.AsType[*profileError](err)
	return &failure{
		code:    exitProfile,
		Title:   "The response breaks the strict profile",
		Message: violation.Error(),
		Hint:    "Use --profile compatible to accept these deviations with a warning.",
	}
}

// isSRPRefusal reports whether the server refused a TLS-SRP sign-in.
func isSRPRefusal(err error) bool {
	return errors.Is(err, srptls.ErrWrongPassword) || errors.Is(err, srptls.ErrUnknownUsername) ||
		errors.Is(err, srptls.ErrAccessDenied)
}

// srpRefusal describes a TLS-SRP sign-in that the server refused.
func srpRefusal(err error) *failure {
	f := &failure{code: exitRejected, Title: "The EST server refused the TLS-SRP sign-in", Message: err.Error()}
	switch {
	case errors.Is(err, srptls.ErrUnknownUsername):
		f.Hint = "The server has no TLS-SRP user of this name. Check --user."
	case errors.Is(err, srptls.ErrAccessDenied):
		f.Hint = "The server refused this TLS-SRP user. It may be locked or over a sign-in limit."
	default:
		// A server that hides which usernames exist answers an unknown one the same way.
		f.Hint = "Check --user and the password."
	}
	return f
}

// refusal describes an HTTP error status from the EST server.
func (s *estSession) refusal(err error) *failure {
	estErr, _ := errors.AsType[est.Error](err)
	status := estErr.StatusCode()
	f := &failure{
		code:       exitRejected,
		Title:      "The EST server refused the request",
		Message:    err.Error(),
		HTTPStatus: status,
		Hint:       s.refusalHint(status),
	}
	if events := s.recorder.Events(); len(events) > 0 {
		if e := events[len(events)-1].EST; e != nil {
			if e.Text != "" {
				f.StatusText = []string{e.Text}
			}
			f.RetryAfter = e.RetryAfter
		}
	}
	return f
}

// refusalHint suggests what to change for an HTTP error status. It returns "" when it has nothing.
func (s *estSession) refusalHint(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "The server did not accept the request. certrally est csrattrs shows what the CA asks for."
	case http.StatusUnauthorized:
		switch {
		case s.creds.user != "":
			return "Check --user and the password."
		case s.creds.token != "":
			return "Check the token."
		case s.creds.key != nil:
			return "The server did not accept the client certificate. Try --user and a password."
		}
		return "Sign in with --user and a password, with --token, or with --cert and --key."
	case http.StatusForbidden:
		return "The credentials are not authorized for this request."
	case http.StatusRequestEntityTooLarge:
		return "The request is larger than the server accepts."
	case http.StatusTooManyRequests:
		return "The server limits requests. Try again later."
	case http.StatusNotImplemented:
		return "The server does not offer this operation."
	case http.StatusServiceUnavailable:
		return "The CA is temporarily unavailable. Try again later."
	case http.StatusAccepted:
		return "The server has not finished the request. Try again later."
	}
	return ""
}

// TLS alerts that say why the server refused the handshake or the client certificate.
const (
	alertHandshakeFailure    = 40
	alertBadCertificate      = 42
	alertUnknownCA           = 48
	alertProtocolVersion     = 70
	alertCertificateRequired = 116
)

// remoteAlert returns the TLS alert the server sent. crypto/tls and go-tls-srp both report it as a
// *net.OpError with Op "remote error" around an unexported alert type of kind uint8.
func remoteAlert(err error) (uint8, bool) {
	opErr, ok := errors.AsType[*net.OpError](err)
	if !ok || opErr.Op != "remote error" || opErr.Err == nil {
		return 0, false
	}
	v := reflect.ValueOf(opErr.Err)
	if v.Kind() != reflect.Uint8 {
		return 0, false
	}
	return uint8(v.Uint()), true //nolint:gosec // G115: a value of kind uint8 fits.
}

// transportHint suggests a fix for a failure to get an EST answer. It returns "" when it has none.
func (s *estSession) transportHint(err, problem error) string {
	alert, isAlert := remoteAlert(problem)
	_, unknownAuthority := errors.AsType[x509.UnknownAuthorityError](problem)
	if retry, ok := errors.AsType[*retryTimeout](err); ok {
		return fmt.Sprintf("Raise --timeout above %s or run the command again later.", retry.wait)
	}
	switch {
	case s.creds.srp && isAlert && (alert == alertHandshakeFailure || alert == alertProtocolVersion):
		// A server without TLS-SRP finds no common cipher suite, or no common version when it needs
		// TLS 1.3, and aborts the handshake.
		return "The server did not accept TLS-SRP. Check that --server names its TLS-SRP port, or leave out --srp."
	case isAlert && alert == alertHandshakeFailure:
		return "The server and certrally share no TLS settings. If this is a TLS-SRP port, sign in with --srp."
	case strings.HasPrefix(problem.Error(), "HTTP 404"):
		return "Check the path and CA label in --server."
	case unknownAuthority:
		return "The TLS certificate of the server is not trusted. Pass its CA with --tls-ca-cert, " +
			"or get the CA certificates with certrally est cacerts --bootstrap. --insecure skips the check for a test."
	case isAlert && (alert == alertBadCertificate || alert == alertUnknownCA || alert == alertCertificateRequired):
		if s.creds.key == nil {
			return "The server asks for a TLS client certificate. Sign in with --cert and --key."
		}
		return "The server did not accept the TLS client certificate in --cert."
	}
	return transportHint(err, problem, s.conn.timeout)
}

// estRun loads the credentials, opens a session and runs op. A failure is reported before the
// error is returned.
func estRun[T any](ctx context.Context, conn *estConnection, auth *estAuth, stdin io.Reader, p *printer, retry bool, op func(context.Context, *estSession) (T, error)) (T, *estSession, error) {
	var zero T
	creds, err := auth.load(stdin, p.stderr)
	if err != nil {
		return zero, nil, err
	}
	s, err := conn.open(p, creds)
	if err != nil {
		return zero, nil, err
	}
	var result T
	err = s.run(ctx, retry, func(ctx context.Context) error {
		var opErr error
		result, opErr = op(ctx, s)
		return opErr
	})
	return result, s, err
}

// serverCertificateFields describes how the server certificate of the last connection relates to
// certs. It returns nothing when there was no connection.
func (s *estSession) serverCertificateFields(certs []*x509.Certificate) []ui.Field {
	info := s.lastTLS()
	if info == nil || len(info.ServerCertificates) == 0 {
		return nil
	}
	value := ui.Sanitize(info.Server) + ", " + chainText(info.ServerCertificates, certs)
	return []ui.Field{{Name: "TLS server", Value: value}}
}

// chainText says whether the server chain verifies against the CA certificates.
func chainText(chain, roots []*x509.Certificate) string {
	if chainsToCerts(chain, roots) {
		return "issued by these CA certificates"
	}
	return "not issued by these CA certificates"
}

// chainsToCerts reports whether the leaf of chain verifies against roots, with the rest of chain
// and roots as intermediates.
func chainsToCerts(chain, roots []*x509.Certificate) bool {
	pool, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
		inter.AddCert(c)
	}
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}
