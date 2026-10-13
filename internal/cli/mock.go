package cli

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"strings"
	"sync"
	"syscall"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/misiektoja/go-pki-cmp/server"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// mockPath is the well-known CMP path, where the mock CA answers.
const mockPath = "/.well-known/cmp"

// mockRequestLimit bounds the request body the request log reads, like the response limit of the client.
const mockRequestLimit = 10 * 1024 * 1024

// mockOptions holds the mock command line.
type mockOptions struct {
	listen     string
	ref        string
	secretFile string
	caOut      string
	force      bool
}

// newMockCommand returns the mock command.
func newMockCommand() *cobra.Command {
	o := &mockOptions{}
	cmd := &cobra.Command{
		Use:   "mock [flags]",
		Short: "Run a local CMP test CA",
		Long: "Run a CMP test CA on this machine, to try certrally or test scripts without a real CA. It issues, " +
			"confirms and revokes certificates and answers the requests for CA certificates, a request template " +
			"and CRLs. It accepts the shared secret for --ref and signatures made with certificates it issued. " +
			"It does not sign composite ML-DSA keys.\n\n" +
			"The shared secret comes from --secret-file or " + secret.EnvVar + ". Without either, a random secret " +
			"is generated and printed. The CA key and everything it issued live in memory and are lost when it " +
			"stops. Stop it with Ctrl-C.",
		Example: "  certrally mock\n" +
			"  certrally mock --listen 127.0.0.1:9000 --ref device-42 --secret-file secret.txt --ca-out ca.pem",
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
	for _, name := range []string{"listen", flagRef} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
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
	sec, err := o.readSecret(cmd.InOrStdin())
	if err != nil {
		return err
	}
	ca, err := mockserver.New(map[string][]byte{o.ref: sec.value}, slog.New(slog.DiscardHandler))
	if err != nil {
		return err
	}
	srv := server.NewCAServer(mockCA{ca},
		server.LightweightPolicy(),
		server.WithSigner(ca.Key(), ca.Cert()),
		server.WithExtraCerts([]*x509.Certificate{ca.Cert()}),
		server.WithSecretLookup(ca),
		server.WithCertificateLookup(ca),
	)
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
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "http://" + addr.String() + mockPath, true
	}
	ip := net.ParseIP(host)
	remote = ip == nil || !ip.IsLoopback()
	if ip != nil && ip.IsUnspecified() {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port) + mockPath, remote
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
	p.result("Mock CA running", []ui.Field{
		{Name: fieldServer, Value: url},
		{Name: "CA", Value: dn.Format(caCert.RawSubject)},
		{Name: "Reference", Value: o.ref},
		{Name: "Secret", Value: secretField},
		{Name: fieldSaved, Value: o.caOut},
	}, nil)

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

// mockCA is the go-pki-cmp example CA with a clear rejection for composite ML-DSA keys, which it
// cannot sign.
type mockCA struct {
	*mockserver.MockCA
}

// IssueCertificate rejects composite ML-DSA keys and lets the example CA issue the rest.
func (c mockCA) IssueCertificate(ctx context.Context, reqType server.RequestType, tmpl *x509.Certificate, sender *server.SenderIdentity) (*server.Response, error) {
	if _, ok := tmpl.PublicKey.(*compositemldsa.PublicKey); ok {
		return nil, &server.Error{
			Status:      pkicmp.StatusRejection,
			FailureInfo: pkicmp.FailBadAlg,
			StatusText:  "the mock CA does not sign composite ML-DSA keys",
		}
	}
	return c.MockCA.IssueCertificate(ctx, reqType, tmpl, sender)
}

// mockLog prints one line for every request the mock CA answers.
type mockLog struct {
	next http.Handler
	p    *printer
	// mu keeps the lines of concurrent requests apart.
	mu sync.Mutex
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
	rec := &responseCapture{ResponseWriter: w, status: http.StatusOK}
	l.next.ServeHTTP(rec, r)

	line := fmt.Sprintf("%s  %s  ->  %s  %s", start.Format(time.TimeOnly),
		describeRequest(r, body), describeResponse(rec), formatRTT(time.Since(start)))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.p.line(line)
}

// describeRequest names a request by its body type, protection and sender, or by method and path
// when it is not a CMP message.
func describeRequest(r *http.Request, body []byte) string {
	m := trace.Summarize(body)
	if m == nil {
		return ui.Sanitize(r.Method + " " + r.URL.Path)
	}
	parts := []string{m.Body, m.Protection}
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
	parts := []string{m.Body}
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
