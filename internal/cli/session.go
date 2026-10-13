package cli

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/charmbracelet/colorprofile"
	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
	"github.com/misiektoja/certrally/internal/ui"
)

// macAlgorithms lists the --mac values.
var macAlgorithms = []string{"pbmac1", "pbm"}

// connection holds the flags that say how to reach a CMP server and which CA to trust.
type connection struct {
	server    string
	caCerts   []string
	tlsCACert string
	recipient string
	timeout   time.Duration
	quiet     bool
}

// addFlags registers the connection flags with the given default timeout.
func (c *connection) addFlags(cmd *cobra.Command, timeout time.Duration, timeoutHelp string) {
	f := cmd.Flags()
	f.StringVar(&c.server, "server", "", "address of the CMP server, an http or https URL")
	f.StringArrayVar(&c.caCerts, "ca-cert", nil,
		"verify the server with this CA certificate instead of trusting the certificates it sends (repeatable)")
	f.StringVar(&c.tlsCACert, "tls-ca-cert", "", "verify HTTPS with these CA certificates instead of the system roots")
	f.StringVar(&c.recipient, "recipient", "", "name of the CA in the request header")
	f.DurationVar(&c.timeout, "timeout", timeout, timeoutHelp)
	f.BoolVarP(&c.quiet, "quiet", "q", false, "print only warnings and errors")
	_ = cmd.MarkFlagRequired("server")
	for _, name := range []string{"server", "recipient", "timeout"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// validate checks the server URL and the timeout.
func (c *connection) validate() error {
	u, err := url.Parse(c.server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--server %q is not an http or https URL", c.server)
	}
	if c.timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	return nil
}

// host returns the host of the server URL for display.
func (c *connection) host() string {
	u, err := url.Parse(c.server)
	if err != nil {
		return c.server
	}
	return u.Host
}

// redactedServer returns the server URL without any password it contains.
func (c *connection) redactedServer() string {
	u, err := url.Parse(c.server)
	if err != nil {
		return c.server
	}
	return u.Redacted()
}

// protection holds the flags that protect requests with a shared secret or a signature.
type protection struct {
	ref        string
	mac        string
	secretFile string
	certFile   string
	keyFile    string
	extraCerts string
	sender     string
}

// addFlags registers the protection flags.
func (p *protection) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&p.ref, "ref", "", "reference that identifies the shared secret to the CA")
	f.StringVar(&p.mac, "mac", "pbmac1", "shared-secret MAC algorithm: pbmac1 or pbm")
	f.StringVar(&p.secretFile, "secret-file", "", "read the shared secret from a file, or - for standard input")
	f.StringVar(&p.certFile, "cert", "", "sign the request with this certificate file, which may include the chain")
	f.StringVar(&p.keyFile, "key", "", "private key for --cert")
	f.StringVar(&p.extraCerts, "extra-certs", "", "send the certificates in this file in extraCerts")
	f.StringVar(&p.sender, "sender", "", "sender name in the request header")
	cmd.MarkFlagsRequiredTogether("cert", "key")
	_ = cmd.RegisterFlagCompletionFunc("mac", fixedCompletion(macAlgorithms))
	for _, name := range []string{"ref", "sender"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// signed reports whether the request is signed rather than MAC-protected.
func (p *protection) signed() bool { return p.certFile != "" }

// validate checks that exactly one protection is chosen.
func (p *protection) validate() error {
	switch {
	case !slices.Contains(macAlgorithms, p.mac):
		return fmt.Errorf("invalid --mac %q, want pbmac1 or pbm", p.mac)
	case p.signed() && (p.ref != "" || p.secretFile != ""):
		return errors.New("choose one protection: --ref with a shared secret, or --cert and --key")
	case !p.signed() && p.ref == "":
		return errors.New("choose a protection: --ref with a shared secret, or --cert and --key")
	}
	return nil
}

// protected is the loaded protection of a request.
type protected struct {
	creds pkicmp.Credentials
	// chain is the signing certificate followed by its chain, or nil for a shared secret.
	chain      []*x509.Certificate
	reqOpts    []client.RequestOption
	clientOpts []client.Option
}

// load reads the credentials. The shared secret may be prompted for on stdin.
func (p *protection) load(stdin io.Reader, prompt io.Writer) (*protected, error) {
	pr := &protected{}
	if p.signed() {
		chain, err := pemfile.ReadCertificates(p.certFile)
		if err != nil {
			return nil, err
		}
		keyData, err := os.ReadFile(p.keyFile)
		if err != nil {
			return nil, err
		}
		key, err := keys.Parse(keyData)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.keyFile, err)
		}
		creds, err := pkicmp.NewSignatureCredentials(key, chain[0], chain[1:]...)
		if err != nil {
			return nil, fmt.Errorf("--cert and --key: %w", err)
		}
		pr.creds, pr.chain = creds, chain
	} else {
		s, err := secret.Source{File: p.secretFile, LookupEnv: os.LookupEnv, Stdin: stdin, Prompt: prompt}.Read()
		if err != nil {
			return nil, err
		}
		var macOpts []pkicmp.MACCredentialOption
		if p.mac == "pbm" {
			macOpts = append(macOpts, pkicmp.WithPBM())
		}
		creds, err := pkicmp.NewMACCredentials(s, macOpts...)
		if err != nil {
			return nil, err
		}
		pr.creds = creds
		// RFC 9483 §4.1.5 identifies the shared secret by the sender common name and the senderKID.
		pr.reqOpts = append(pr.reqOpts, client.WithSenderKID([]byte(p.ref)))
		if p.sender == "" {
			pr.reqOpts = append(pr.reqOpts, client.WithSender(pkix.Name{CommonName: p.ref}))
		}
	}
	if p.sender != "" {
		name, err := dn.ParseName(p.sender)
		if err != nil {
			return nil, fmt.Errorf("--sender: %w", err)
		}
		pr.reqOpts = append(pr.reqOpts, client.WithSender(name))
	}
	if p.extraCerts != "" {
		certs, err := pemfile.ReadCertificates(p.extraCerts)
		if err != nil {
			return nil, err
		}
		pr.clientOpts = append(pr.clientOpts, client.WithExtraCerts(certs))
	}
	return pr, nil
}

// session is an open connection: an HTTP client that records every exchange and the trust state.
type session struct {
	conn     *connection
	errOut   io.Writer
	recorder *trace.Recorder
	http     *http.Client
	// pool holds the trust anchors. Without --ca-cert it fills from the first response.
	pool *x509.CertPool
	// anchors lists the certificates in pool.
	anchors []*x509.Certificate
	// pinned is set when --ca-cert names the CA, so nothing the server sends is trusted by itself.
	pinned  bool
	caCerts []*x509.Certificate
	// ladder draws the exchange unless --quiet is set.
	ladder *ui.Ladder
}

// open prepares a session. Certificates after the first one in chain, the chain of the signing
// certificate, are trusted as well, because the user named them.
func (c *connection) open(stderr io.Writer, chain []*x509.Certificate) (*session, error) {
	s := &session{conn: c, errOut: colorprofile.NewWriter(stderr, os.Environ()), pool: x509.NewCertPool()}
	for _, path := range c.caCerts {
		certs, err := pemfile.ReadCertificates(path)
		if err != nil {
			return nil, err
		}
		s.caCerts = append(s.caCerts, certs...)
	}
	s.pinned = len(s.caCerts) > 0
	for _, cert := range s.caCerts {
		s.trust(cert)
	}
	if len(chain) > 1 {
		for _, cert := range chain[1:] {
			s.trust(cert)
		}
	}

	next := http.DefaultTransport
	if c.tlsCACert != "" {
		certs, err := pemfile.ReadCertificates(c.tlsCACert)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		for _, cert := range certs {
			roots.AddCert(cert)
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		next = t
	}
	s.recorder = &trace.Recorder{Next: next}
	trustFirst := !s.pinned
	s.recorder.OnEvent = func(ev trace.Event) {
		// The recorder reports a response before the client verifies it, so certificates added here
		// already count for that response.
		if trustFirst && ev.Kind == trace.Response && ev.Message != nil {
			trustFirst = false
			s.trustResponse(ev.DER)
		}
		if s.ladder != nil {
			s.ladder.Event(ev)
		}
	}
	s.http = &http.Client{Transport: s.recorder}
	return s, nil
}

// startLadder starts drawing the exchange unless --quiet is set.
func (s *session) startLadder() {
	if !s.conn.quiet {
		s.ladder = ui.NewLadder(s.errOut, "certrally", s.conn.host())
	}
}

// endLadder separates the ladder from the report that follows it.
func (s *session) endLadder() {
	if s.ladder != nil && len(s.recorder.Events()) > 0 {
		_, _ = fmt.Fprintln(s.errOut)
	}
}

// trustResponse adds the certificates of a response to the trust anchors. This trusts the CA the
// user pointed certrally at, as identified by the TLS certificate of an https server.
func (s *session) trustResponse(der []byte) {
	msg, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		return
	}
	certs := msg.ExtraCerts
	if rep := certRep(msg.Body); rep != nil {
		certs = append(certs, rep.CAPubs...)
	}
	for _, c := range certs {
		if cert, err := c.Parse(); err == nil {
			s.trust(cert)
		}
	}
}

// trust adds cert to the trust anchors.
func (s *session) trust(cert *x509.Certificate) {
	s.pool.AddCert(cert)
	s.anchors = append(s.anchors, cert)
}

// certRep returns the content of an ip, cp or kup body, or nil for other bodies.
func certRep(body *pkicmp.PKIBody) *pkicmp.CertRepMessage {
	var rep *pkicmp.CertRepMessage
	var err error
	switch body.Type {
	case pkicmp.BodyTypeIP:
		rep, err = body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = body.KUP()
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	return rep
}

// client returns a CMP client that uses the session.
func (s *session) client(extra ...client.Option) (*client.Client, error) {
	opts := []client.Option{client.WithHTTPClient(s.http), client.WithTrustedCAs(s.pool)}
	if s.pinned {
		// Some CAs leave their certificate out of responses, so a named CA certificate is also
		// a candidate signer.
		opts = append(opts, client.WithServerCerts(s.caCerts))
	}
	if s.conn.recipient != "" {
		name, err := dn.ParseName(s.conn.recipient)
		if err != nil {
			return nil, fmt.Errorf("--recipient: %w", err)
		}
		opts = append(opts, client.WithRecipient(name))
	}
	return client.NewClient(s.conn.server, append(opts, extra...)...), nil
}
