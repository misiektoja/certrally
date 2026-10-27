package cli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/misiektoja/go-pki-cmp/client"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
	"github.com/spf13/cobra"

	"github.com/misiektoja/certrally/internal/dn"
	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/profile"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
)

// macPBM is the --mac value that selects PasswordBasedMac.
const macPBM = "pbm"

// macAlgorithms lists the --mac values.
var macAlgorithms = []string{"pbmac1", macPBM}

// hashChoices lists the --hash values with their digests.
var hashChoices = []struct {
	name string
	hash crypto.Hash
}{
	{"sha1", crypto.SHA1},
	{"sha256", crypto.SHA256},
	{"sha384", crypto.SHA384},
	{"sha512", crypto.SHA512},
}

// hashNames lists the --hash values.
var hashNames = func() []string {
	names := make([]string, 0, len(hashChoices))
	for _, c := range hashChoices {
		names = append(names, c.name)
	}
	return names
}()

// hashes maps the --hash values to digests.
var hashes = func() map[string]crypto.Hash {
	m := make(map[string]crypto.Hash, len(hashChoices))
	for _, c := range hashChoices {
		m[c.name] = c.hash
	}
	return m
}()

// connection holds the flags that say how to reach a CMP server and which CA to trust.
type connection struct {
	server    string
	caCerts   []string
	tlsCACert string
	// insecure skips the check of the TLS certificate of an https server.
	insecure bool
	// proxy is the --proxy URL, which replaces the proxy from the environment.
	proxy     string
	recipient string
	timeout   time.Duration
	capture   string
	profile   string
	// resumed holds the trust of the run that started the transaction this run resumes. It takes the
	// place of --ca-cert, --tls-ca-cert and trust on first response.
	resumed *savedTrust
}

// savedTrust is the trust of a session, kept so that a later run can resume its transaction with
// the same trust.
type savedTrust struct {
	// caCerts are the --ca-cert certificates, which pin the CA.
	caCerts []*x509.Certificate
	// anchors are every certificate the session trusted.
	anchors []*x509.Certificate
	// tlsRoots verify HTTPS instead of the system roots when there are any.
	tlsRoots []*x509.Certificate
}

// addFlags registers the connection flags with the given default timeout.
func (c *connection) addFlags(cmd *cobra.Command, timeout time.Duration, timeoutHelp string) {
	f := cmd.Flags()
	f.StringVar(&c.server, "server", "", "address of the CMP server, an http or https URL")
	f.StringArrayVar(&c.caCerts, "ca-cert", nil,
		"verify the server with this CA certificate instead of trusting the certificates it sends (repeatable)")
	f.StringVar(&c.tlsCACert, flagTLSCACert, "", "verify HTTPS with these CA certificates instead of the system roots")
	f.BoolVar(&c.insecure, flagInsecure, false, insecureHelp)
	f.StringVar(&c.proxy, flagProxy, "", proxyHelp)
	f.StringVar(&c.recipient, "recipient", "", "name of the CA in the request header")
	f.DurationVar(&c.timeout, "timeout", timeout, timeoutHelp)
	f.StringVar(&c.capture, "capture", "", "append the exchanged messages to this file as JSON Lines")
	f.StringVar(&c.profile, "profile", profile.Compatible,
		"how to treat responses that break RFC 9483: compatible warns, strict fails")
	_ = cmd.MarkFlagRequired("server")
	cmd.MarkFlagsMutuallyExclusive(flagTLSCACert, flagInsecure)
	_ = cmd.RegisterFlagCompletionFunc("profile", fixedCompletion(profile.Names))
	for _, name := range []string{"server", "recipient", "timeout", flagProxy} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// Names and help of the TLS flags that the CMP and EST commands share.
const (
	flagTLSCACert = "tls-ca-cert"
	flagInsecure  = "insecure"
	insecureHelp  = "skip the check of the TLS certificate of the server, which lets anyone pose as the server"
	flagProxy     = "proxy"
	proxyHelp     = "connect through this http or https proxy instead of the one HTTPS_PROXY names"
)

// validate checks the server URL, the timeout and the profile.
func (c *connection) validate() error {
	if !isServerURL(c.server) {
		return fmt.Errorf("--server %q is not an http or https URL", c.server)
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

// URL schemes of servers and proxies.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// isServerURL reports whether s is an http or https URL with a host.
func isServerURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == schemeHTTP || u.Scheme == schemeHTTPS) && u.Host != ""
}

// parseProxy returns the --proxy URL, or nil when the flag is empty.
func parseProxy(s string) (*url.URL, error) {
	if s == "" {
		return nil, nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Host == "" {
		return nil, fmt.Errorf("--proxy %q is not an http or https URL", s)
	}
	return u, nil
}

// checkCapture rejects a --capture file that is also an output of the command.
func (c *connection) checkCapture(outputs ...string) error {
	if c.capture == "" {
		return nil
	}
	for _, out := range outputs {
		if out != "" && out != stdoutPath && filepath.Clean(out) == filepath.Clean(c.capture) {
			return fmt.Errorf("%s is given for --capture and for an output", c.capture)
		}
	}
	return nil
}

// Names of the flags that several commands define. The enroll wizard sets some of them.
const (
	flagRef     = "ref"
	flagSecret  = "secret"
	flagSAN     = "san"
	flagSubject = "subject"
	flagServer  = "server"
	flagTimeout = "timeout"
)

// protection holds the flags that protect requests with a shared secret or a signature.
type protection struct {
	ref        string
	mac        string
	secretFile string
	// secretValue is the shared secret given with --secret.
	secretValue secret.Value
	certFile    string
	keyFile     string
	keyPassword
	extraCerts string
	sender     string
	// iterations is the MAC iteration count. Zero keeps the default of go-pki-cmp.
	iterations int
	// hash names the digest of the signatures and of a PasswordBasedMac. Empty keeps the defaults.
	hash        string
	generalInfo []string
	// secret is a shared secret typed into the enroll wizard. It takes the place of the other sources.
	secret []byte
	// raCert and raKey name the certificate and key of a registration authority that forwards every
	// request in a nested message. Only enroll and poll take them.
	raCert string
	raKey  string
}

// secretHelp is the help of --secret.
const secretHelp = "shared secret, which other users of this machine can see in the process list"

// Flags of the registration authority that forwards the requests of enroll and poll.
const (
	flagRACert = "ra-cert"
	flagRAKey  = "ra-key"
)

// addFlags registers the protection flags.
func (p *protection) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&p.ref, flagRef, "", "reference that identifies the shared secret to the CA")
	f.StringVar(&p.mac, "mac", "pbmac1", "algorithm of the shared-secret MAC: pbmac1 or pbm")
	f.Var(&p.secretValue, flagSecret, secretHelp)
	f.StringVar(&p.secretFile, "secret-file", "", "read the shared secret from a file, or - for standard input")
	f.StringVar(&p.certFile, "cert", "", "sign the request with this certificate file, which may include the chain")
	f.StringVar(&p.keyFile, "key", "", "private key for --cert")
	p.keyPassword.addFlags(cmd)
	f.StringVar(&p.extraCerts, "extra-certs", "", "send the certificates in this file in extraCerts")
	f.StringVar(&p.sender, "sender", "", "sender name in the request header")
	f.IntVar(&p.iterations, "iterations", 0, "iteration count of the shared-secret MAC (default 10000)")
	f.StringVar(&p.hash, "hash", "", "digest of the signatures made for the request and of --mac pbm: "+
		"sha1, sha256, sha384 or sha512 (default by key type, sha256 for pbm)")
	f.StringArrayVar(&p.generalInfo, "general-info", nil,
		"add a generalInfo item to the request header: OID:int:N, OID:str:TEXT or OID:hex:DER (repeatable)")
	cmd.MarkFlagsRequiredTogether("cert", "key")
	cmd.MarkFlagsMutuallyExclusive(flagSecret, "secret-file")
	_ = cmd.RegisterFlagCompletionFunc("mac", fixedCompletion(macAlgorithms))
	_ = cmd.RegisterFlagCompletionFunc("hash", fixedCompletion(hashNames))
	for _, name := range []string{flagRef, flagSecret, "sender", "iterations", "general-info"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
}

// addRAFlags registers --ra-cert and --ra-key.
func (p *protection) addRAFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&p.raCert, flagRACert, "",
		"forward each request as a registration authority, signed with this certificate file, which may include the chain")
	f.StringVar(&p.raKey, flagRAKey, "", "private key for --ra-cert")
	cmd.MarkFlagsRequiredTogether(flagRACert, flagRAKey)
}

// signed reports whether the request is signed rather than MAC-protected.
func (p *protection) signed() bool { return p.certFile != "" }

// validate checks that exactly one protection is chosen.
func (p *protection) validate() error {
	switch {
	case !slices.Contains(macAlgorithms, p.mac):
		return fmt.Errorf("invalid --mac %q, want pbmac1 or pbm", p.mac)
	case p.signed() && (p.ref != "" || p.secretFile != "" || p.secretValue.Bytes() != nil):
		return errors.New("choose one protection: --ref with a shared secret, or --cert and --key")
	case !p.signed() && p.ref == "":
		return errors.New("choose a protection: --ref with a shared secret, or --cert and --key")
	case p.iterations < 0:
		return errors.New("--iterations must be positive")
	case p.iterations != 0 && p.signed():
		return errors.New("--iterations sets the shared-secret MAC, so it cannot be combined with --cert")
	case p.hash != "" && !slices.Contains(hashNames, p.hash):
		return fmt.Errorf("invalid --hash %q, want one of %s", p.hash, strings.Join(hashNames, ", "))
	case p.hash != "" && !p.signed() && p.mac != macPBM:
		return errors.New("--hash with a shared secret needs --mac pbm, because PBMAC1 always uses SHA-256")
	}
	return p.checkStdin("--secret-file", p.secretFile)
}

// digest returns the digest that --hash names, or zero for the defaults.
func (p *protection) digest() crypto.Hash { return hashes[p.hash] }

// takesDigest reports whether the key of pub signs with a chosen digest, which RSA and ECDSA keys do.
func takesDigest(pub crypto.PublicKey) bool {
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return true
	}
	return false
}

// protected is the loaded protection of a request.
type protected struct {
	creds pkicmp.Credentials
	// chain is the signing certificate followed by its chain. It is nil for a shared secret.
	chain      []*x509.Certificate
	reqOpts    []client.RequestOption
	clientOpts []client.Option
	// ra is the certificate of the registration authority that forwards the requests, nil without one.
	ra *x509.Certificate
}

// load reads the credentials. The shared secret may be prompted for on stdin.
func (p *protection) load(stdin io.Reader, prompt io.Writer) (*protected, error) {
	pr := &protected{}
	items, err := parseGeneralInfo(p.generalInfo)
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		pr.reqOpts = append(pr.reqOpts, client.WithGeneralInfo(items...))
	}
	hash := p.digest()
	if hash != 0 {
		pr.reqOpts = append(pr.reqOpts, client.WithPOPHash(hash))
	}
	if p.signed() {
		chain, err := pemfile.ReadCertificates(p.certFile)
		if err != nil {
			return nil, err
		}
		key, err := p.keyPassword.loadSigner(p.keyFile, stdin, prompt)
		if err != nil {
			return nil, err
		}
		creds, err := pkicmp.NewSignatureCredentials(key, chain[0], chain[1:]...)
		if err != nil {
			return nil, fmt.Errorf("--cert and --key: %w", err)
		}
		if hash != 0 {
			if !takesDigest(key.Public()) {
				return nil, fmt.Errorf("--hash applies to RSA and ECDSA keys, not to the %s key in %s",
					keys.Describe(key.Public()), p.keyFile)
			}
			if creds, err = creds.WithHash(hash); err != nil {
				return nil, fmt.Errorf("--hash: %w", err)
			}
		}
		pr.creds, pr.chain = creds, chain
	} else {
		s := p.secret
		if s == nil {
			var err error
			s, err = secret.Source{
				Value:     p.secretValue.Bytes(),
				File:      p.secretFile,
				LookupEnv: os.LookupEnv,
				Stdin:     stdin,
				Prompt:    prompt,
			}.Read()
			if err != nil {
				return nil, err
			}
		}
		var macOpts []pkicmp.MACCredentialOption
		switch {
		case hash != 0:
			macOpts = append(macOpts, pkicmp.WithPBMAlgorithms(hash, hash))
		case p.mac == macPBM:
			macOpts = append(macOpts, pkicmp.WithPBM())
		}
		if p.iterations != 0 {
			// The CA echoes the count in its responses, so the client must accept it too.
			minimum := min(p.iterations, pkicmp.DefaultMinMACIterationCount)
			maximum := max(p.iterations, pkicmp.DefaultMaxMACIterationCount)
			macOpts = append(macOpts,
				pkicmp.WithMACIterationCount(p.iterations), pkicmp.WithMACIterationLimits(minimum, maximum))
			pr.clientOpts = append(pr.clientOpts, client.WithMACIterationLimits(minimum, maximum))
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
	if p.raCert != "" {
		if err := p.loadRA(pr, stdin, prompt); err != nil {
			return nil, err
		}
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

// loadRA reads the registration authority certificate and key and makes the client of pr wrap every
// request in a nested message signed with them.
func (p *protection) loadRA(pr *protected, stdin io.Reader, prompt io.Writer) error {
	chain, err := pemfile.ReadCertificates(p.raCert)
	if err != nil {
		return err
	}
	key, err := p.keyPassword.loadSigner(p.raKey, stdin, prompt)
	if err != nil {
		return err
	}
	creds, err := pkicmp.NewSignatureCredentials(key, chain[0], chain[1:]...)
	if err != nil {
		return fmt.Errorf("--%s and --%s: %w", flagRACert, flagRAKey, err)
	}
	pr.clientOpts = append(pr.clientOpts, client.WithRegistrationAuthority(creds))
	pr.ra = chain[0]
	return nil
}

// parseGeneralInfo parses the --general-info values into header items.
func parseGeneralInfo(values []string) ([]pkicmp.InfoTypeAndValue, error) {
	items := make([]pkicmp.InfoTypeAndValue, 0, len(values))
	for _, v := range values {
		item, err := parseInfoTypeAndValue(v)
		if err != nil {
			return nil, fmt.Errorf("--general-info %q: %w", v, err)
		}
		items = append(items, item)
	}
	return items, nil
}

// parseInfoTypeAndValue parses OID:int:N, OID:str:TEXT or OID:hex:DER. An int value becomes an
// INTEGER, a str value a UTF8String and a hex value the DER of one value as given.
func parseInfoTypeAndValue(s string) (pkicmp.InfoTypeAndValue, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return pkicmp.InfoTypeAndValue{}, errors.New("want OID:int:N, OID:str:TEXT or OID:hex:DER")
	}
	oid, err := dn.ParseOID(parts[0])
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, err
	}
	var value []byte
	switch kind, text := parts[1], parts[2]; kind {
	case "int":
		n, ok := new(big.Int).SetString(text, 10)
		if !ok {
			return pkicmp.InfoTypeAndValue{}, fmt.Errorf("%q is not an integer", text)
		}
		value, err = asn1.Marshal(n)
	case "str":
		value, err = asn1.MarshalWithParams(text, "utf8")
	case "hex":
		value, err = hex.DecodeString(text)
		if err == nil {
			var rest []byte
			if rest, err = asn1.Unmarshal(value, &asn1.RawValue{}); err == nil && len(rest) > 0 {
				err = errors.New("the DER holds more than one value")
			}
		}
	default:
		return pkicmp.InfoTypeAndValue{}, fmt.Errorf("unknown value type %q, want int, str or hex", kind)
	}
	if err != nil {
		return pkicmp.InfoTypeAndValue{}, err
	}
	return pkicmp.InfoTypeAndValue{InfoType: oid, InfoValue: value}, nil
}

// session is an open connection to a CMP server: an HTTP client that records every exchange and the
// trust state.
type session struct {
	*recording
	conn *connection
	http *http.Client
	// pool holds the trust anchors. Without --ca-cert it fills from the first response.
	pool *x509.CertPool
	// anchors lists the certificates in pool.
	anchors []*x509.Certificate
	// pinned is set when --ca-cert names the CA, so nothing the server sends is trusted by itself.
	pinned  bool
	caCerts []*x509.Certificate
	// tlsRoots are the --tls-ca-cert certificates.
	tlsRoots []*x509.Certificate
	// ra is the certificate of the registration authority that forwards the requests, nil without one.
	ra *x509.Certificate
}

// open prepares a session and registers it with p. Certificates after the first one in chain, the
// chain of the signing certificate, are trusted as well, because the user named them.
func (c *connection) open(p *printer, chain []*x509.Certificate) (*session, error) {
	s := &session{conn: c, pool: x509.NewCertPool()}
	if c.resumed != nil {
		s.caCerts, s.tlsRoots = c.resumed.caCerts, c.resumed.tlsRoots
	} else {
		for _, path := range c.caCerts {
			certs, err := pemfile.ReadCertificates(path)
			if err != nil {
				return nil, err
			}
			s.caCerts = append(s.caCerts, certs...)
		}
		if c.tlsCACert != "" {
			certs, err := pemfile.ReadCertificates(c.tlsCACert)
			if err != nil {
				return nil, err
			}
			s.tlsRoots = certs
		}
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
	if c.resumed != nil {
		for _, cert := range c.resumed.anchors {
			if !slices.ContainsFunc(s.anchors, cert.Equal) {
				s.trust(cert)
			}
		}
	}

	rec, err := openRecording(p, recordingOptions{
		server:   c.server,
		profile:  c.profile,
		capture:  c.capture,
		insecure: c.insecure,
	})
	if err != nil {
		return nil, err
	}
	s.recording = rec
	proxy, err := parseProxy(c.proxy)
	if err != nil {
		return nil, err
	}
	s.recorder.Next = newTransport(s.tlsRoots, c.insecure, proxy)
	// A resumed transaction keeps the trust of the run that started it, which already had its first
	// response.
	trustFirst := !s.pinned && c.resumed == nil
	plainHTTP := strings.HasPrefix(strings.ToLower(c.server), schemeHTTP+"://")
	s.observe = func(ev trace.Event) {
		// The recorder reports a response before the client verifies it, so certificates added here
		// already count for that response.
		if trustFirst && ev.Kind == trace.Response && ev.Message != nil {
			trustFirst = false
			s.trustResponse(ev.DER, plainHTTP)
		}
	}
	s.recorder.Inspect = s.inspect
	s.http = &http.Client{Transport: s.recorder}
	return s, nil
}

// newTransport returns the HTTP transport of a CMP connection. roots replace the system roots for
// HTTPS when there are any. insecure skips the check of the server certificate instead. proxy
// replaces the proxy from the environment when it is set.
func newTransport(roots []*x509.Certificate, insecure bool, proxy *url.URL) http.RoundTripper {
	if len(roots) == 0 && !insecure && proxy == nil {
		return http.DefaultTransport
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	if proxy != nil {
		t.Proxy = http.ProxyURL(proxy)
	}
	switch {
	case insecure:
		t.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // G402: --insecure asks for it and the report warns.
		}
	case len(roots) > 0:
		pool := x509.NewCertPool()
		for _, cert := range roots {
			pool.AddCert(cert)
		}
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return t
}

// inspect checks a response against the profile. A strict session stops a response that breaks a
// rule before the client accepts it. A rejection is not stopped, because the reason the CA gives
// matters more, so its deviations are reported as warnings like in a compatible session.
func (s *session) inspect(request, response trace.Event) error {
	req, err := pkicmp.ParsePKIMessage(request.DER)
	if err != nil {
		return nil
	}
	resp, err := pkicmp.ParsePKIMessage(response.DER)
	if err != nil {
		return nil
	}
	findings := profile.Check(req, resp, s.anchors)
	return s.report(findings, response.Message.Status != pkicmp.StatusRejection.String())
}

// plainHTTPTrustWarning is the warning of a session that trusted its first response over plain HTTP.
const plainHTTPTrustWarning = "The certificates of the first response were trusted over plain HTTP, " +
	"which nothing authenticates. Name the CA with --ca-cert unless you trust the network."

// trustResponse adds the certificates of a response to the trust anchors and reports them with
// their fingerprints, so the user can compare them with what the CA published. This trusts the CA
// the user pointed certrally at, as identified by the TLS certificate of an https server. Over
// plain HTTP, which plainHTTP reports, nothing identifies the server, so the report warns.
func (s *session) trustResponse(der []byte, plainHTTP bool) {
	msg, err := pkicmp.ParsePKIMessage(der)
	if err != nil {
		return
	}
	certs := msg.ExtraCerts
	if rep := certRep(msg.Body); rep != nil {
		certs = append(certs, rep.CAPubs...)
	}
	var trusted []*x509.Certificate
	for _, c := range certs {
		cert, err := c.Parse()
		// A response often carries the CA certificate in both extraCerts and caPubs.
		if err != nil || slices.ContainsFunc(s.anchors, cert.Equal) {
			continue
		}
		s.trust(cert)
		trusted = append(trusted, cert)
	}
	if len(trusted) == 0 {
		return
	}
	s.p.trustedOnFirstResponse(trusted)
	if plainHTTP {
		s.warnAfterLadder(plainHTTPTrustWarning)
	}
}

// trust adds cert to the trust anchors.
func (s *session) trust(cert *x509.Certificate) {
	s.pool.AddCert(cert)
	s.anchors = append(s.anchors, cert)
}

// saveTrust returns the trust of the session for a run that resumes its transaction.
func (s *session) saveTrust() *savedTrust {
	return &savedTrust{caCerts: s.caCerts, anchors: s.anchors, tlsRoots: s.tlsRoots}
}

// certRep returns the content of an ip, cp or kup body. It returns nil for other bodies.
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
		// a candidate signer. caPubs of a MAC-protected response would otherwise become trusted CAs
		// next to --ca-cert.
		opts = append(opts, client.WithServerCerts(s.caCerts), client.WithoutCAPubsTrust())
	}
	if s.allowSenderKIDMismatch() {
		opts = append(opts, client.WithSenderKIDMismatch())
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

// allowSenderKIDMismatch reports whether a signed response may carry a senderKID that names none of its
// candidate signers. Some CAs copy the senderKID of the request into their responses. The compatible
// profile accepts that with a warning from the profile check. The signer must still chain to the trusted
// CAs, name the sender and verify the signature.
func (s *session) allowSenderKIDMismatch() bool {
	return s.conn.profile == profile.Compatible
}

// exchange runs one operation against the server. It loads the credentials, opens a session and
// draws the ladder around op. A failure is reported before the error is returned.
func exchange[T any](ctx context.Context, conn *connection, prot *protection, stdin io.Reader, p *printer, op func(context.Context, *client.Client, *protected) (T, error)) (T, *session, error) {
	var zero T
	pr, err := prot.load(stdin, p.stderr)
	if err != nil {
		return zero, nil, err
	}
	s, err := conn.open(p, pr.chain)
	if err != nil {
		return zero, nil, err
	}
	c, err := s.client(pr.clientOpts...)
	if err != nil {
		return zero, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, conn.timeout)
	defer cancel()
	s.startLadder()
	result, err := op(ctx, c, pr)
	s.endLadder()
	if err != nil {
		return zero, s, s.fail(err)
	}
	return result, s, nil
}
