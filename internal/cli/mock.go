package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// mockPath is the well-known CMP path, where the mock CA answers.
const mockPath = "/.well-known/cmp"

// mockRequestLimit bounds the request body the request log reads, like the response limit of the client.
const mockRequestLimit = 10 * 1024 * 1024

// mockConfirmWait is the default confirmWaitTime, that of go-pki-cmp.
const mockConfirmWait = 10 * time.Second

// mockOptions holds the mock command line.
type mockOptions struct {
	listen     string
	ref        string
	secretFile string
	caOut      string
	force      bool
	// The fault flags change how the CA answers, to test how a client copes.
	waiting         int
	checkAfter      time.Duration
	reject          string
	implicitConfirm bool
	strict          bool
	macIterations   string
	confirmWait     time.Duration
	accept          []string
	requireRA       bool
}

// acceptOption is a --accept value: a deviation from RFC 9483 that the mock CA accepts on request.
type acceptOption struct {
	name   string
	help   string
	option func() server.Option
}

// acceptOptions lists the --accept values.
var acceptOptions = []acceptOption{
	{"missing-pollreq-nonce", "a pollReq without recipNonce", server.WithOptionalPollReqRecipNonce},
	{"missing-certconf-nonce", "a certConf without recipNonce", server.WithOptionalCertConfRecipNonce},
	{"missing-subject", "a certificate template without subject", server.WithOptionalSubject},
	{"any-cert-req-id", "a certReqId other than 0, repeated in the response", server.WithAnyCertReqID},
	{"missing-revocation-reason", "a revocation request without reason code", server.WithOptionalRevocationReason},
	{"missing-revocation-issuer", "a revocation request without issuer", server.WithOptionalRevocationIssuer},
	{"poposkinput", "a signature proof of possession over poposkInput", server.WithPoposkInputVariants},
	{"signature-pop", "no proof of possession in a request signed with a certificate for the key",
		server.WithSignatureProtectionPOP},
	{"sha1", "SHA-1 signatures in the protection and the proof of possession", server.WithSHA1Signatures},
	{"mac-revocation", "revocation requests not signed with the revoked certificate, such as MAC-protected ones",
		server.WithMACRevocation},
	{"raw-subject", "the subject as encoded in the request, keeping every attribute, order and string type",
		server.WithRawSubject},
	{"encrypted-cert-pop", "the encrypted certificate proof of possession", server.WithEncryptedCertificatePOP},
	{"challenge-pop", "the challenge-response proof of possession", server.WithChallengeResponsePOP},
}

// acceptNames lists the --accept values in the order of acceptOptions.
var acceptNames = func() []string {
	names := make([]string, 0, len(acceptOptions))
	for _, a := range acceptOptions {
		names = append(names, a.name)
	}
	return names
}()

// failInfoNames lists the --reject values, the PKIFailureInfo names in bit order.
var failInfoNames = func() []string {
	names := make([]string, 0, 27)
	for i := range 27 {
		names = append(names, trace.FailureNames(pkicmp.PKIFailureInfo(1)<<(31-i))...)
	}
	return names
}()

// newMockCommand returns the mock command.
func newMockCommand() *cobra.Command {
	o := &mockOptions{}
	cmd := &cobra.Command{
		Use:   "mock [flags]",
		Short: "Run a local CMP test CA",
		Long: "Run a CMP test CA on this machine, to try certrally or test scripts without a real CA. It issues, " +
			"confirms and revokes certificates and answers the requests for CA certificates, a request template " +
			"and CRLs. It accepts the shared secret for --ref and signatures made with certificates it issued. " +
			"It generates the key pair for enroll --central-keygen and signs it with a key generation authority " +
			"certificate it issued. It accepts requests that a registration authority forwards in a nested " +
			"message signed with a certificate it issued with the cmcRA extended key usage.\n\n" +
			"The shared secret comes from --secret-file or " + secret.EnvVar + ". Without either, a random secret " +
			"is generated and printed. The CA key and everything it issued live in memory and are lost when it " +
			"stops. Stop it with Ctrl-C.\n\n" +
			"The fault flags make the CA delay, reject or confirm requests differently and accept deviations " +
			"from RFC 9483, to test how a client copes. --accept takes one of:\n" + acceptHelp(),
		Example: "  certrally mock\n" +
			"  certrally mock --listen 127.0.0.1:9000 --ref device-42 --secret-file secret.txt --ca-out ca.pem\n" +
			"  certrally mock --waiting 2 --check-after 5s\n" +
			"  certrally mock --reject badCertTemplate:'subject not allowed'\n" +
			"  certrally mock --strict --mac-iterations 100-10000 --accept sha1\n" +
			"  certrally mock --require-ra",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMock(cmd, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.listen, "listen", "127.0.0.1:8080", "address and port to listen on. Port 0 picks a free port")
	f.StringVar(&o.ref, flagRef, "demo", "reference that identifies the shared secret")
	f.StringVar(&o.secretFile, "secret-file", "", "read the shared secret from a file, or - for standard input")
	f.StringVar(&o.caOut, "ca-out", "", "save the CA certificate to this file, for --ca-cert")
	f.BoolVar(&o.force, "force", false, "replace an existing --ca-out file")
	f.IntVar(&o.waiting, "waiting", 0,
		"answer certificate and revocation requests with status waiting and decide them on poll N")
	f.DurationVar(&o.checkAfter, "check-after", time.Second,
		"time a waiting response tells the client to wait before it polls")
	f.StringVar(&o.reject, "reject", "",
		"reject every certificate and revocation request with this failInfo, such as badRequest or badCertTemplate:TEXT")
	f.BoolVar(&o.implicitConfirm, "grant-implicit-confirm", false,
		"grant implicitConfirm, so a certificate needs no certConf")
	f.BoolVar(&o.strict, "strict", false,
		"refuse requests that break RFC 9483 instead of accepting the usual deviations")
	f.StringVar(&o.macIterations, "mac-iterations", "",
		"accept only MAC iteration counts from MIN to MAX, such as 100-10000")
	f.DurationVar(&o.confirmWait, "confirm-wait", mockConfirmWait,
		"time the client has to confirm a certificate, sent as confirmWaitTime")
	f.StringArrayVar(&o.accept, "accept", nil,
		"accept a deviation from RFC 9483, one of the names listed above (repeatable)")
	f.BoolVar(&o.requireRA, "require-ra", false,
		"refuse certificate requests that no registration authority forwarded")
	_ = cmd.RegisterFlagCompletionFunc("accept", fixedCompletion(acceptNames))
	_ = cmd.RegisterFlagCompletionFunc("reject", fixedCompletion(failInfoNames))
	for _, name := range []string{"listen", flagRef, "waiting", "check-after", "mac-iterations", "confirm-wait"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// acceptHelp lists the --accept values with their meaning, one per line.
func acceptHelp() string {
	var b strings.Builder
	for _, a := range acceptOptions {
		fmt.Fprintf(&b, "  %-26s %s\n", a.name, a.help)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// faults holds the parsed fault flags.
type faults struct {
	reject        *server.Error
	minIterations int
	maxIterations int
	options       []server.Option
}

// parseFaults checks the fault flags and returns the server options and CA behaviour they select.
func (o *mockOptions) parseFaults() (*faults, error) {
	f := &faults{}
	switch {
	case o.waiting < 0:
		return nil, errors.New("--waiting must not be negative")
	case o.checkAfter < 0:
		return nil, errors.New("--check-after must not be negative")
	case o.confirmWait <= 0:
		return nil, errors.New("--confirm-wait must be positive")
	}
	if o.reject != "" {
		rejection, err := parseRejection(o.reject)
		if err != nil {
			return nil, err
		}
		f.reject = rejection
	}
	if o.macIterations != "" {
		minimum, maximum, err := parseIterationRange(o.macIterations)
		if err != nil {
			return nil, err
		}
		f.minIterations, f.maxIterations = minimum, maximum
		f.options = append(f.options, server.WithMACIterationLimits(minimum, maximum))
	}
	if o.implicitConfirm {
		f.options = append(f.options, server.WithImplicitConfirm())
	}
	if o.strict {
		f.options = append(f.options, server.WithStrictProfileValidation())
	}
	f.options = append(f.options, server.WithConfirmWaitTime(o.confirmWait))
	for _, name := range o.accept {
		i := slices.IndexFunc(acceptOptions, func(a acceptOption) bool { return a.name == name })
		if i < 0 {
			return nil, fmt.Errorf("invalid --accept %q, want one of %s", name, strings.Join(acceptNames, ", "))
		}
		f.options = append(f.options, acceptOptions[i].option())
	}
	return f, nil
}

// parseRejection parses a --reject value: a failInfo name, optionally followed by a colon and the
// statusString text.
func parseRejection(s string) (*server.Error, error) {
	name, text, _ := strings.Cut(s, ":")
	for i := range 27 {
		bit := pkicmp.PKIFailureInfo(1) << (31 - i)
		if strings.EqualFold(bit.String(), name) {
			return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: bit, StatusText: text}, nil
		}
	}
	return nil, fmt.Errorf("invalid --reject %q, want a failInfo name, optionally followed by :TEXT: %s",
		s, strings.Join(failInfoNames, ", "))
}

// parseIterationRange parses a --mac-iterations value of the form MIN-MAX.
func parseIterationRange(s string) (minimum, maximum int, err error) {
	first, second, ok := strings.Cut(s, "-")
	if ok {
		minimum, err = strconv.Atoi(first)
		if err == nil {
			maximum, err = strconv.Atoi(second)
		}
	}
	if !ok || err != nil || minimum < 1 || maximum < minimum {
		return 0, 0, fmt.Errorf("invalid --mac-iterations %q, want MIN-MAX with 1 <= MIN <= MAX, such as 100-10000", s)
	}
	return minimum, maximum, nil
}

// mockSecret is the shared secret of the mock CA and where it came from.
type mockSecret struct {
	value []byte
	// generated is set when the secret was made up because no source provided one.
	generated bool
}

// readSecret reads the shared secret from --secret-file or the environment. It generates a random
// one instead of prompting, because the user needs to know the secret to use it.
func (o *mockOptions) readSecret(stdin io.Reader) (mockSecret, error) {
	src := secret.Source{File: o.secretFile, LookupEnv: os.LookupEnv}
	if o.secretFile == "-" {
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

// runMock serves the mock CA until the context ends or the process is interrupted.
func runMock(cmd *cobra.Command, o *mockOptions) error {
	if o.ref == "" {
		return errors.New("--ref must not be empty")
	}
	if o.caOut != "" {
		if err := pemfile.CheckWritable(o.caOut, o.force); err != nil {
			return err
		}
	}
	flt, err := o.parseFaults()
	if err != nil {
		return err
	}
	sec, err := o.readSecret(cmd.InOrStdin())
	if err != nil {
		return err
	}
	ca, err := mockserver.New(map[string][]byte{o.ref: sec.value}, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	faultCA := &faultCA{
		MockCA:              ca,
		waiting:             o.waiting,
		checkAfter:          o.checkAfter,
		reject:              flt.reject,
		authorizeRevocation: slices.Contains(o.accept, "mac-revocation"),
		requireRA:           o.requireRA,
		pending:             map[string]*pendingDecision{},
	}
	opts := []server.Option{
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithExtraCerts([]*x509.Certificate{ca.Cert()}),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
		server.WithCentralKeyGeneration(mockKeyGenerator{}, ca.KGAKey(), ca.KGACert()),
		server.WithRAAuthorizer(faultCA),
	}
	srv := server.NewCAServer(faultCA, server.LightweightPolicy(), slices.Concat(opts, flt.options)...)
	if err := srv.Err(); err != nil {
		return err
	}

	ln, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", o.listen)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	// The CA file is written once the address is taken, so a failed start leaves no file behind.
	if o.caOut != "" {
		caPEM := pemfile.EncodeCertificates([]*x509.Certificate{ca.Cert()})
		if err := pemfile.Write(o.caOut, caPEM, 0o644, o.force); err != nil {
			_ = ln.Close()
			return err
		}
	}
	p := newPrinter(cmd, outputOptions{})
	url, remote := mockURL(ln.Addr())
	o.report(p, url, ca.Cert(), sec)
	if remote {
		p.warn("The mock CA accepts requests from other hosts. Anyone who reaches it and knows the secret gets certificates.")
	}

	mux := http.NewServeMux()
	mux.Handle(mockPath, srv)
	mux.Handle(mockPath+"/", srv)
	httpSrv := &http.Server{
		Handler:           &mockLog{next: mux, p: p},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- httpSrv.Serve(ln) }()
	go cleanupTransactions(ctx, srv)

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdown); err != nil {
		return err
	}
	p.line("Mock CA stopped")
	return nil
}

// cleanupTransactions drops transactions whose certificate was never confirmed, as a long-running
// server must.
func cleanupTransactions(ctx context.Context, srv *server.Server) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			srv.CleanupExpired()
		}
	}
}

// mockURL returns the server URL for addr and reports whether other hosts can reach it.
func mockURL(addr net.Addr) (url string, remote bool) {
	hostPort, remote := mockHostPort(addr)
	return "http://" + hostPort + mockPath, remote
}

// mockHostPort returns the host and port that reach addr and reports whether other hosts can reach
// it. The unspecified address is reached as localhost.
func mockHostPort(addr net.Addr) (hostPort string, remote bool) {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), true
	}
	ip := net.ParseIP(host)
	remote = ip == nil || !ip.IsLoopback()
	if ip != nil && ip.IsUnspecified() {
		host = "localhost"
	}
	return net.JoinHostPort(host, port), remote
}

// report prints how to reach the mock CA and an enroll command that works against it.
func (o *mockOptions) report(p *printer, url string, caCert *x509.Certificate, sec mockSecret) {
	secretField := "from " + secret.EnvVar
	switch {
	case sec.generated:
		secretField = string(sec.value) + " (generated)"
	case o.secretFile != "":
		secretField = "from " + o.secretFile
	}
	fields := []ui.Field{
		{Name: fieldServer, Value: url},
		{Name: "CA", Value: dn.Format(caCert.RawSubject)},
		{Name: "Reference", Value: o.ref},
		{Name: "Secret", Value: secretField},
		{Name: fieldSaved, Value: o.caOut},
	}
	p.result("Mock CA running", slices.Concat(fields, o.faultFields()), nil)

	args := []string{programName, "enroll", "--server", url, "--ref", shellQuote(o.ref)}
	if o.caOut != "" {
		args = append(args, "--ca-cert", shellQuote(o.caOut))
	}
	if o.secretFile != "" && o.secretFile != "-" {
		args = append(args, "--secret-file", shellQuote(o.secretFile))
	}
	args = append(args, "--cert-out", "device.pem", "--key-out", "device.key")
	command := strings.Join(args, " ")
	if sec.generated {
		command = secret.EnvVar + "=" + string(sec.value) + " " + command
	}
	p.line("\nEnroll a certificate from another terminal:\n  " + command + "\n\nPress Ctrl-C to stop.\n")
}

// faultFields describes the fault flags in use, for the startup report.
func (o *mockOptions) faultFields() []ui.Field {
	var fields []ui.Field
	if o.waiting > 0 {
		fields = append(fields, ui.Field{Name: "Waiting",
			Value: fmt.Sprintf("decides on poll %d, checkAfter %s", o.waiting, o.checkAfter)})
	}
	if o.reject != "" {
		fields = append(fields, ui.Field{Name: "Rejecting", Value: ui.Sanitize(o.reject)})
	}
	if o.implicitConfirm {
		fields = append(fields, ui.Field{Name: fieldConfirmation, Value: "implicitConfirm granted"})
	}
	if o.strict {
		fields = append(fields, ui.Field{Name: "Profile", Value: "strict"})
	}
	if o.macIterations != "" {
		fields = append(fields, ui.Field{Name: "MAC iterations", Value: o.macIterations})
	}
	if o.confirmWait != mockConfirmWait {
		fields = append(fields, ui.Field{Name: "Confirm wait", Value: o.confirmWait.String()})
	}
	if len(o.accept) > 0 {
		fields = append(fields, ui.Field{Name: "Accepting", Value: strings.Join(o.accept, ", ")})
	}
	if o.requireRA {
		fields = append(fields, ui.Field{Name: "Registration", Value: "only requests a registration authority forwards"})
	}
	return fields
}

// faultCA wraps the example CA with the delays and rejections of the fault flags. Everything else,
// such as confirmation and the secret lookup, passes through to the example CA.
type faultCA struct {
	*mockserver.MockCA
	// waiting is the poll on which a request is decided. Zero decides it at once.
	waiting    int
	checkAfter time.Duration
	// reject, when set, is the answer to every certificate and revocation request.
	reject *server.Error
	// authorizeRevocation allows revocation requests that are not signed with the certificate they
	// revoke.
	authorizeRevocation bool
	// requireRA refuses certificate requests that no registration authority forwarded.
	requireRA bool
	mu        sync.Mutex
	// pending holds the delayed requests by pollRef.
	pending map[string]*pendingDecision
	nextRef int
}

// pendingDecision is a request that waits for polls before the CA decides it.
type pendingDecision struct {
	polls  int
	decide func(context.Context) (*server.Response, error)
}

// IssueCertificate issues the certificate, after the configured polls, unless every request is rejected
// or --require-ra refuses a request that no registration authority forwarded. A request for a
// registration authority certificate needs no RA, so the first RA can enroll.
func (c *faultCA) IssueCertificate(ctx context.Context, reqType server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	if c.requireRA && sender.RA == nil && !requestsRA(tmpl) {
		return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized,
			StatusText: "the mock CA accepts only requests that a registration authority forwards"}
	}
	return c.delay(ctx, func(ctx context.Context) (*server.Response, error) {
		return c.MockCA.IssueCertificate(ctx, reqType, tmpl, sender)
	})
}

// requestsRA reports whether tmpl asks for the id-kp-cmcRA extended key usage.
func requestsRA(tmpl *x509.Certificate) bool {
	for _, ext := range tmpl.ExtraExtensions {
		if !ext.Id.Equal(oidExtKeyUsage) {
			continue
		}
		var purposes []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &purposes); err == nil {
			return slices.ContainsFunc(purposes, oidKeyPurposeCMCRA.Equal)
		}
	}
	return false
}

// AuthorizeRA accepts the registration authorities the example CA accepts and notes the RA in the
// request log.
func (c *faultCA) AuthorizeRA(ctx context.Context, ra *server.SenderIdentity, req *pkicmp.PKIMessage, sender *server.SenderIdentity) error {
	if err := c.MockCA.AuthorizeRA(ctx, ra, req, sender); err != nil {
		return err
	}
	addMockNote(ctx, "forwarded by RA  "+ui.Sanitize(dn.Format(ra.Certificate.RawSubject)))
	return nil
}

// mockKeyGenerator generates the key pairs of requests for central key generation.
type mockKeyGenerator struct{}

// GenerateKey generates an ECDSA P-256 key when the request leaves the choice to the CA and otherwise
// a key of any type enroll --key-type offers. A requested RSA key has 2048 bits, since the request
// cannot name the size.
func (mockKeyGenerator) GenerateKey(ctx context.Context, algorithm *pkicmp.AlgorithmIdentifier, _ *server.SenderIdentity) (*server.GeneratedKey, error) {
	name := keys.DefaultType
	if algorithm != nil {
		t, ok := keys.TypeForAlgorithm(algorithm.Algorithm, algorithm.Parameters)
		if !ok {
			return nil, &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadAlg,
				StatusText: "the mock CA does not generate keys of algorithm " + algorithm.Algorithm.String()}
		}
		name = t.Name
	}
	key, err := keys.Generate(name)
	if err != nil {
		return nil, err
	}
	der, err := keys.Marshal(key)
	if err != nil {
		return nil, err
	}
	pub := keys.Public(key)
	addMockNote(ctx, "generated  "+keys.Describe(pub)+" key")
	return &server.GeneratedKey{PrivateKey: der, PublicKey: pub}, nil
}

// RevokeCertificate revokes the certificate, after the configured polls, unless every request is rejected.
// A revocation is noted in the request log with what the request asked for.
func (c *faultCA) RevokeCertificate(ctx context.Context, req *server.RevocationRequest, sender *server.SenderIdentity) error {
	resp, err := c.delay(ctx, func(ctx context.Context) (*server.Response, error) {
		if err := c.MockCA.RevokeCertificate(ctx, req, sender); err != nil {
			return nil, err
		}
		addMockNote(ctx, describeRevocation(req))
		return nil, nil
	})
	if resp != nil && resp.Waiting != nil {
		return &server.WaitingError{WaitingResponse: *resp.Waiting}
	}
	return err
}

// describeRevocation names a revoked certificate by its serial number and the reason, with the
// invalidity date when the request gave one.
func describeRevocation(req *server.RevocationRequest) string {
	line := fmt.Sprintf("revoked  serial %s  %s", hexBytes(req.SerialNumber.Bytes()), req.Reason)
	if !req.InvalidityDate.IsZero() {
		line += "  invalidity date " + req.InvalidityDate.UTC().Format(time.RFC3339)
	}
	return line
}

// AuthorizeRevocation decides on a revocation request that is not signed with the certificate it
// revokes. The example CA has no such policy, so the request is refused unless --accept
// mac-revocation allows every such request.
func (c *faultCA) AuthorizeRevocation(context.Context, *server.RevocationRequest, *server.SenderIdentity) error {
	if c.authorizeRevocation {
		return nil
	}
	return &server.Error{Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailNotAuthorized,
		StatusText: "only the certificate holder may revoke it"}
}

// delay applies the fault flags to a decision. It rejects the request when --reject is set and
// otherwise decides it at once or, with --waiting, keeps it for the polls.
func (c *faultCA) delay(ctx context.Context, decide func(context.Context) (*server.Response, error)) (*server.Response, error) {
	if c.reject != nil {
		rejection := *c.reject
		decide = func(context.Context) (*server.Response, error) { return nil, &rejection }
	}
	if c.waiting == 0 {
		return decide(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextRef++
	ref := strconv.Itoa(c.nextRef)
	c.pending[ref] = &pendingDecision{decide: decide}
	return c.waitingResponse(ref), nil
}

// waitingResponse tells the client to poll for the request ref.
func (c *faultCA) waitingResponse(ref string) *server.Response {
	return &server.Response{
		Waiting: &server.WaitingResponse{CheckAfter: c.checkAfter, Reason: "waiting for approval", PollRef: ref},
	}
}

// CheckPending answers a poll: the request keeps waiting until the configured poll, which decides it.
func (c *faultCA) CheckPending(ctx context.Context, pollRef string, _ *server.SenderIdentity) (*server.Response, error) {
	c.mu.Lock()
	d, ok := c.pending[pollRef]
	if !ok {
		c.mu.Unlock()
		return nil, &server.Error{
			Status: pkicmp.StatusRejection, FailureInfo: pkicmp.FailBadRequest, StatusText: "unknown pollRef",
		}
	}
	d.polls++
	if d.polls < c.waiting {
		c.mu.Unlock()
		return c.waitingResponse(pollRef), nil
	}
	delete(c.pending, pollRef)
	c.mu.Unlock()
	return d.decide(ctx)
}

// mockLog prints one line for every request the mock CA answers, followed by the notes the CA
// added while it handled the request.
type mockLog struct {
	next http.Handler
	p    *printer
	// mu keeps the lines of concurrent requests apart.
	mu sync.Mutex
}

// mockNotes collects what the CA did for one request, such as a revocation, for the request log.
type mockNotes struct {
	mu    sync.Mutex
	lines []string
}

// mockNotesKey is the context key of the mockNotes of a request.
type mockNotesKey struct{}

// addMockNote adds a line to the request log below the request that ctx belongs to. A context
// without a request log, such as one of a test, drops the note.
func addMockNote(ctx context.Context, line string) {
	notes, ok := ctx.Value(mockNotesKey{}).(*mockNotes)
	if !ok {
		return
	}
	notes.mu.Lock()
	defer notes.mu.Unlock()
	notes.lines = append(notes.lines, line)
}

// ServeHTTP answers the request and prints what was asked and answered.
func (l *mockLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, err := io.ReadAll(io.LimitReader(r.Body, mockRequestLimit))
	if err != nil {
		http.Error(w, "cannot read the request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	notes := &mockNotes{}
	r = r.WithContext(context.WithValue(r.Context(), mockNotesKey{}, notes))
	rec := &responseCapture{ResponseWriter: w, status: http.StatusOK}
	l.next.ServeHTTP(rec, r)

	stamp := start.Format(time.TimeOnly)
	lines := []string{fmt.Sprintf("%s  %s  ->  %s  %s", stamp,
		describeRequest(r, body), describeResponse(rec), formatRTT(time.Since(start)))}
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

// describeRequest names a request by its body type, protection and sender, or by method and path
// when it is not a CMP message.
func describeRequest(r *http.Request, body []byte) string {
	m := trace.Summarize(body)
	if m == nil {
		return ui.Sanitize(r.Method + " " + r.URL.Path)
	}
	parts := []string{m.Label(), m.Protection}
	if m.Sender != "" {
		parts = append(parts, ui.Sanitize(m.Sender))
	}
	return strings.Join(parts, "  ")
}

// describeResponse names a response by its body type and status, or by its HTTP status when it is
// not a CMP message.
func describeResponse(rec *responseCapture) string {
	m := trace.Summarize(rec.body.Bytes())
	if m == nil {
		return fmt.Sprintf("HTTP %d", rec.status)
	}
	parts := []string{m.Label()}
	if m.Status != "" {
		parts = append(parts, m.Status)
	}
	parts = append(parts, trace.FailureNames(m.FailInfo)...)
	return strings.Join(parts, "  ")
}

// responseCapture passes a response through and keeps a copy of its status and body.
type responseCapture struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

// WriteHeader records the status.
func (c *responseCapture) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

// Write keeps a copy of the body.
func (c *responseCapture) Write(b []byte) (int, error) {
	c.body.Write(b)
	return c.ResponseWriter.Write(b)
}
