package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/misiektoja/go-composite-mldsa/compositex509"
	est "github.com/misiektoja/go-pki-est"
	srptls "github.com/misiektoja/go-tls-srp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/estca"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// estMockRequestLimit bounds a request body. A request for an SLH-DSA key can exceed the 64 KiB
// default of go-pki-est.
const estMockRequestLimit = 1 << 20

// estMockSRPGroupBits is the SRP group of the TLS-SRP verifier.
const estMockSRPGroupBits = 3072

// estMockOptions holds the est mock command line.
type estMockOptions struct {
	listen       string
	srpListen    string
	user         string
	password     secret.Value
	passwordFile string
	token        secret.Value
	tokenFile    string
	caOut        string
	force        bool
	retryAfter   int
}

// newESTMockCommand returns est mock.
func newESTMockCommand() *cobra.Command {
	o := &estMockOptions{}
	cmd := &cobra.Command{
		Use:   mockUse,
		Short: "Run a local EST test CA",
		Long: "Run an EST test CA on this machine, to try certrally or test scripts without a real CA. It " +
			"answers cacerts, csrattrs, simpleenroll, simplereenroll and serverkeygen over HTTPS with a " +
			"certificate it issued itself.\n\n" +
			"Enrollment accepts the password of --user over HTTP Basic authentication or a TLS client " +
			"certificate the CA issued. Renewal also accepts the password without a client certificate. With " +
			"--srp-listen, a second port signs in --user with TLS-SRP and the same password. The " +
			"password comes from --password, --password-file or " + secret.PasswordEnvVar + ". Without any of " +
			"them, a random password is generated and printed. A bearer token from --token, --token-file or " +
			secret.TokenEnvVar + " is accepted too. The CA key and everything it issued live in memory and are lost when it " +
			"stops. Stop it with Ctrl-C.",
		Example: "  certrally est mock\n" +
			"  certrally est mock --listen 127.0.0.1:9443 --user device-42 --password-file password.txt --ca-out ca.pem\n" +
			"  certrally est mock --srp-listen 127.0.0.1:8444",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runESTMock(cmd, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.listen, flagListen, "127.0.0.1:8443", "address and port to listen on. Port 0 picks a free port")
	f.StringVar(&o.srpListen, "srp-listen", "", "also serve TLS-SRP on this address and port, such as 127.0.0.1:8444")
	f.StringVar(&o.user, "user", "demo", "username that HTTP Basic authentication accepts")
	f.Var(&o.password, flagPassword, "password of --user, which other users of this machine can see in the process list")
	f.StringVar(&o.passwordFile, "password-file", "", "read the password from a file, or - for standard input")
	f.Var(&o.token, flagToken,
		"also accept this bearer token, which other users of this machine can see in the process list")
	f.StringVar(&o.tokenFile, flagTokenFile, "", "also accept the bearer token in this file, or - for standard input")
	cmd.MarkFlagsMutuallyExclusive(flagPassword, "password-file")
	cmd.MarkFlagsMutuallyExclusive(flagToken, flagTokenFile)
	f.StringVar(&o.caOut, "ca-out", "", "save the CA certificate to this file, for --tls-ca-cert")
	f.BoolVar(&o.force, "force", false, "replace an existing --ca-out file")
	f.IntVar(&o.retryAfter, "retry-after", 0,
		"answer the first request for each key with 202 Accepted and this Retry-After in seconds")
	for _, name := range []string{flagListen, "srp-listen", "user", flagPassword, flagToken, "retry-after"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// readPassword reads the password from --password, --password-file or the environment. It generates
// a random one instead of prompting, because the user needs to know the password to use it.
func (o *estMockOptions) readPassword(stdin io.Reader) (mockSecret, error) {
	src := secret.Source{Kind: secret.Password, Value: o.password.Bytes(), File: o.passwordFile, LookupEnv: os.LookupEnv}
	if o.passwordFile == "-" {
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

// readToken reads the bearer token from --token, --token-file or the environment. Without any of
// them there is no token to accept.
func (o *estMockOptions) readToken(stdin io.Reader) ([]byte, error) {
	src := secret.Source{Kind: secret.Token, Value: o.token.Bytes(), File: o.tokenFile, LookupEnv: os.LookupEnv}
	if o.tokenFile == "-" {
		src.Stdin = stdin
	}
	value, err := src.Read()
	if errors.Is(err, secret.ErrMissing) {
		return nil, nil
	}
	return value, err
}

// runESTMock serves the EST test CA until the context ends or the process is interrupted.
func runESTMock(cmd *cobra.Command, o *estMockOptions) error {
	if o.user == "" {
		return errors.New("--user must not be empty")
	}
	if o.retryAfter < 0 {
		return errors.New("--retry-after must not be negative")
	}
	if o.passwordFile == "-" && o.tokenFile == "-" {
		return errors.New("--password-file and --token-file cannot both read standard input")
	}
	p := newPrinter(cmd, outputOptions{})
	if err := p.confirmOutputs(&o.force, o.caOut); err != nil {
		return err
	}
	password, err := o.readPassword(cmd.InOrStdin())
	if err != nil {
		return err
	}
	token, err := o.readToken(cmd.InOrStdin())
	if err != nil {
		return err
	}
	ca, err := estca.New()
	if err != nil {
		return err
	}
	ca.RetryAfter = o.retryAfter
	router, err := newESTMockRouter(ca, o.user, password.value, token)
	if err != nil {
		return err
	}

	ln, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", o.listen)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	var srpLn net.Listener
	closeListeners := func() {
		_ = ln.Close()
		if srpLn != nil {
			_ = srpLn.Close()
		}
	}
	if o.srpListen != "" {
		if srpLn, err = o.listenSRP(cmd.Context(), password.value); err != nil {
			_ = ln.Close()
			return err
		}
	}
	serverCert, err := ca.ServerCertificate(mockHosts(ln.Addr()))
	if err != nil {
		closeListeners()
		return err
	}
	// The CA file is written once the addresses are taken, so a failed start leaves no file behind.
	if o.caOut != "" {
		caPEM := pemfile.EncodeCertificates([]*x509.Certificate{ca.Certificate()})
		if err := pemfile.Write(o.caOut, caPEM, 0o644, o.force); err != nil {
			closeListeners()
			return err
		}
	}

	hostPort, remote := mockHostPort(ln.Addr())
	urls := estMockURLs{https: "https://" + hostPort}
	if srpLn != nil {
		srpHostPort, srpRemote := mockHostPort(srpLn.Addr())
		urls.srp = "https://" + srpHostPort
		remote = remote || srpRemote
	}
	o.report(p, urls, ca.Certificate(), password, len(token) > 0)
	if remote {
		p.warn("The mock CA accepts requests from other hosts. " +
			"Anyone who reaches it and knows the password gets certificates.")
	}

	log := &estMockLog{next: router, p: p}
	httpSrv := &http.Server{
		Handler: log,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			// The router checks a client certificate itself, so that it can tell why it refuses one.
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	servers := []*http.Server{httpSrv}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 2)
	go func() { served <- httpSrv.ServeTLS(ln, "", "") }()
	if srpLn != nil {
		srpSrv := newSRPMockServer(log)
		servers = append(servers, srpSrv)
		go func() { served <- srpSrv.Serve(srpLn) }()
	}

	var serveErr error
	select {
	case serveErr = <-served:
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil && serveErr == nil {
			serveErr = err
		}
	}
	if serveErr != nil {
		return serveErr
	}
	p.line("Mock CA stopped")
	return nil
}

// listenSRP listens on --srp-listen for TLS-SRP sign-ins of --user with password.
func (o *estMockOptions) listenSRP(ctx context.Context, password []byte) (net.Listener, error) {
	group, err := srptls.GroupByBits(estMockSRPGroupBits)
	if err != nil {
		return nil, err
	}
	salt, err := srptls.NewSalt(rand.Reader)
	if err != nil {
		return nil, err
	}
	verifier, err := srptls.NewVerifier(group, []byte(o.user), password, salt)
	if err != nil {
		return nil, err
	}
	inner, err := (&net.ListenConfig{}).Listen(ctx, "tcp", o.srpListen)
	if err != nil {
		return nil, fmt.Errorf("--srp-listen: %w", err)
	}
	user := o.user
	return srptls.NewListener(inner, &srptls.Config{
		// The mock names an unknown user, so that clients can test how they report it.
		GetVerifier: func(info *srptls.ClientHelloInfo) (*srptls.Verifier, error) {
			if info.Username != user {
				return nil, srptls.ErrUnknownUsername
			}
			return verifier, nil
		},
	}), nil
}

// srpConnKey is the request context key of the TLS-SRP connection.
type srpConnKey struct{}

// newSRPMockServer returns the HTTP server of the TLS-SRP port. It passes the TLS-SRP username to
// the EST router and logs failed sign-ins.
func newSRPMockServer(log *estMockLog) *http.Server {
	return &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, ok := r.Context().Value(srpConnKey{}).(*srptls.Conn); ok {
				r = r.WithContext(est.WithSRPUsername(r.Context(), c.ConnectionState().SRPUsername))
			}
			log.ServeHTTP(w, r)
		}),
		// net/http sets Request.TLS only for crypto/tls connections, so the handler reads the
		// TLS-SRP state from the connection instead.
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, srpConnKey{}, conn)
		},
		// net/http does not report handshake failures of other TLS stacks. The handshake error of a
		// connection that closes before it completes is kept, so Handshake returns it again.
		ConnState: func(conn net.Conn, state http.ConnState) {
			tc, ok := conn.(*srptls.Conn)
			if !ok || state != http.StateClosed || tc.ConnectionState().HandshakeComplete {
				return
			}
			if err := tc.Handshake(); err != nil {
				log.print(fmt.Sprintf("%s  TLS-SRP sign-in from %s failed: %v",
					time.Now().Format(time.TimeOnly), conn.RemoteAddr(), err))
			}
		},
		// The TLS-SRP handshake runs in the first read, so the header timeout includes it.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// newESTMockRouter returns the EST handler of the test CA. It accepts the password of user, the
// bearer token when there is one, a client certificate the CA issued and a TLS-SRP sign-in.
func newESTMockRouter(ca *estca.CA, user string, password, token []byte) (http.Handler, error) {
	cfg := &est.ServerConfig{
		CA: ca,
		CheckBasicAuth: func(ctx context.Context, r *http.Request, _, username, pass string) error {
			if signedInByTLS(ctx, r, ca) {
				return nil
			}
			userOK := subtle.ConstantTimeCompare([]byte(username), []byte(user)) == 1
			passOK := subtle.ConstantTimeCompare([]byte(pass), password) == 1
			if userOK && passOK {
				return nil
			}
			return errors.New("sign in with the password, the token or a certificate of this CA")
		},
		PasswordRenewal:   true,
		CheckCSRSignature: compositex509.CheckCertificateRequestSignature,
		VerifyClientCertificate: func(_ context.Context, _ *http.Request, _ string, cert *x509.Certificate) error {
			return ca.Verify(cert)
		},
		MaxRequestBody: estMockRequestLimit,
		// A browser that stores Strict-Transport-Security for localhost refuses certificate warnings
		// on every local port.
		OmitStrictTransportSecurity: true,
	}
	// The server runs CheckBearerToken in place of CheckBasicAuth for a request with a bearer token,
	// and only a token that CheckBearerToken accepted signs in for renewal without a certificate.
	// Without a token the hook stays unset, so a bearer token gets the usual Basic challenge.
	if len(token) > 0 {
		cfg.CheckBearerToken = func(ctx context.Context, r *http.Request, _, bearer string) error {
			if signedInByTLS(ctx, r, ca) || subtle.ConstantTimeCompare([]byte(bearer), token) == 1 {
				return nil
			}
			return errors.New("sign in with the token, the password or a certificate of this CA")
		}
	}
	return est.NewRouter(cfg)
}

// signedInByTLS reports whether the connection of r signed in with TLS-SRP or with a client
// certificate that ca issued.
func signedInByTLS(ctx context.Context, r *http.Request, ca *estca.CA) bool {
	if est.SRPUsernameFromContext(ctx) != "" {
		return true
	}
	return r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && ca.Verify(r.TLS.PeerCertificates[0]) == nil
}

// mockHosts returns the names the server certificate covers: localhost and the address listened
// on, unless it is the unspecified address.
func mockHosts(addr net.Addr) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return hosts
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() && !ip.IsLoopback() {
		hosts = append(hosts, host)
	}
	return hosts
}

// estMockURLs are the addresses of the test CA. srp is empty without --srp-listen.
type estMockURLs struct {
	https string
	srp   string
}

// report prints how to reach the test CA and the commands that work against it. hasToken says
// whether a bearer token is accepted.
func (o *estMockOptions) report(p *printer, urls estMockURLs, caCert *x509.Certificate, password mockSecret, hasToken bool) {
	passwordField := "from " + secret.PasswordEnvVar
	switch {
	case password.generated:
		passwordField = string(password.value) + " (generated)"
	case o.password.Bytes() != nil:
		passwordField = "from --password"
	case o.passwordFile != "":
		passwordField = "from " + o.passwordFile
	}
	tokenField := valueNone
	switch {
	case o.token.Bytes() != nil:
		tokenField = "from --" + flagToken
	case o.tokenFile != "":
		tokenField = "from " + o.tokenFile
	case hasToken:
		tokenField = "from " + secret.TokenEnvVar
	}
	sum := sha256.Sum256(caCert.Raw)
	p.result("EST mock CA running", []ui.Field{
		{Name: fieldServer, Value: urls.https},
		{Name: "TLS-SRP", Value: urls.srp},
		{Name: "CA", Value: dn.Format(caCert.RawSubject)},
		{Name: fieldSHA256, Value: hex.EncodeToString(sum[:])},
		{Name: "User", Value: o.user},
		{Name: "Password", Value: passwordField},
		{Name: "Token", Value: tokenField},
		{Name: fieldSaved, Value: o.caOut},
	}, nil)

	caFile := o.caOut
	var lines []string
	if caFile == "" {
		caFile = "ca.pem"
		lines = append(lines, strings.Join([]string{
			programName, estCommand, "cacerts", "--server", urls.https, "--bootstrap",
			"--fingerprint", hex.EncodeToString(sum[:]), "--out", caFile,
		}, " "))
	}
	lines = append(lines, o.enrollCommand(password, "--server", urls.https, "--tls-ca-cert", shellQuote(caFile)))
	if hasToken {
		lines = append(lines, o.tokenCommand("--server", urls.https, "--tls-ca-cert", shellQuote(caFile)))
	}
	if urls.srp != "" {
		lines = append(lines, o.enrollCommand(password, "--server", urls.srp, "--srp"))
	}
	p.line("\nEnroll a certificate from another terminal:\n  " + strings.Join(lines, "\n  ") +
		"\n\nPress Ctrl-C to stop.\n")
}

// enrollCommand returns an est enroll command line that signs in with the password of --user.
// server holds the flags that reach the server.
func (o *estMockOptions) enrollCommand(password mockSecret, server ...string) string {
	args := append([]string{programName, estCommand, estEnroll}, server...)
	args = append(args, "--user", shellQuote(o.user))
	if o.passwordFile != "" && o.passwordFile != "-" {
		args = append(args, "--password-file", shellQuote(o.passwordFile))
	}
	args = append(args, enrollOutputs...)
	command := strings.Join(args, " ")
	if password.generated {
		command = secret.PasswordEnvVar + "=" + string(password.value) + " " + command
	}
	return command
}

// enrollOutputs are the request and output flags of the printed enroll commands.
var enrollOutputs = []string{"--subject", "CN=device", "--cert-out", "device.pem", "--key-out", "device.key"}

// tokenCommand returns an est enroll command line that signs in with the bearer token. server
// holds the flags that reach the server.
func (o *estMockOptions) tokenCommand(server ...string) string {
	args := append([]string{programName, estCommand, estEnroll}, server...)
	if o.tokenFile != "" && o.tokenFile != "-" {
		args = append(args, "--"+flagTokenFile, shellQuote(o.tokenFile))
	} else {
		args = append(args, "--"+flagToken)
	}
	return strings.Join(append(args, enrollOutputs...), " ")
}

// estMockLog prints one line for every request the test CA answers.
type estMockLog struct {
	next http.Handler
	p    *printer
	// mu keeps the lines of concurrent requests apart.
	mu sync.Mutex
}

// ServeHTTP answers the request and prints what was asked and answered.
func (l *estMockLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := io.ReadAll(io.LimitReader(r.Body, estMockRequestLimit+1))
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	rec := &responseCapture{ResponseWriter: w, status: http.StatusOK}
	l.next.ServeHTTP(rec, r)

	req, _ := trace.SummarizeESTRequest(r, body)
	resp, _ := trace.SummarizeESTResponse(req.Operation,
		&http.Response{StatusCode: rec.status, Header: rec.Header()}, rec.body.Bytes())
	l.print(fmt.Sprintf("%s  %s  ->  %s  %s", start.Format(time.TimeOnly),
		describeESTRequest(req), describeESTResponse(rec.status, resp), formatRTT(time.Since(start))))
}

// print prints one log line.
func (l *estMockLog) print(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.p.line(line)
}

// describeESTRequest names a request by its method, operation and subject.
func describeESTRequest(s *trace.ESTSummary) string {
	parts := []string{s.Method, s.Operation}
	if s.Operation == "" {
		parts[1] = s.Path
	}
	if s.Subject != "" {
		parts = append(parts, s.Subject)
	}
	return ui.Sanitize(strings.Join(parts, "  "))
}

// describeESTResponse names a response by its status and content.
func describeESTResponse(status int, s *trace.ESTSummary) string {
	parts := []string{fmt.Sprintf("HTTP %d", status)}
	if s.Content != "" {
		parts = append(parts, s.Content)
	}
	if s.Certificates > 0 {
		parts = append(parts, count(s.Certificates, "certificate", "certificates"))
	}
	if s.RetryAfter != nil {
		parts = append(parts, fmt.Sprintf("retry after %d s", *s.RetryAfter))
	}
	if s.Text != "" {
		parts = append(parts, fmt.Sprintf("%q", ui.Sanitize(s.Text)))
	}
	return strings.Join(parts, "  ")
}
