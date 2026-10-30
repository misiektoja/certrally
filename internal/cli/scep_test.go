package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: SCEP fingerprints may be SHA-1.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/misiektoja/go-pkcs7"
	"github.com/misiektoja/go-scep/scepserver"

	"github.com/misiektoja/certrally/internal/pemfile"
	"github.com/misiektoja/certrally/internal/scepca"
	"github.com/misiektoja/certrally/internal/secret"
	"github.com/misiektoja/certrally/internal/trace"
)

// scepTestChallenge is the challenge password the SCEP test servers accept.
const scepTestChallenge = "s3cret-challenge"

// scepTestServer is a SCEP server that runs for one test.
type scepTestServer struct {
	url string
	ca  *scepca.CA
	// caFile holds the GetCACert certificates, for --ca-cert.
	caFile string
}

// useChallenge makes the challenge password available through the environment, or removes it when
// empty.
func useChallenge(t *testing.T, value string) {
	t.Helper()
	isolateColorEnv(t)
	t.Setenv(secret.ChallengeEnvVar, value)
	if value == "" {
		if err := os.Unsetenv(secret.ChallengeEnvVar); err != nil {
			t.Fatal(err)
		}
	}
}

// startSCEPServer serves a test CA made with opts. wrap, if set, wraps the SCEP handler, so that a
// test can change answers the way some CA products do.
func startSCEPServer(t *testing.T, opts scepca.Options, handlerOpts scepserver.Options, wrap func(http.Handler) http.Handler) *scepTestServer {
	t.Helper()
	ca, err := scepca.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ca.Handler(handlerOpts)
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler = h
	if wrap != nil {
		handler = wrap(h)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	certs, err := ca.CACertificates(context.Background(), opts.Name)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "scep-ca.pem")
	writeFile(t, caFile, pemfile.EncodeCertificates(certs))
	return &scepTestServer{url: srv.URL + "/scep", ca: ca, caFile: caFile}
}

// args returns a scep command line for the server.
func (s *scepTestServer) args(command string, extra ...string) []string {
	return append([]string{"scep", command, "--server", s.url}, extra...)
}

// trusted returns a scep command line for the server that trusts the CA certificates in caFile.
func (s *scepTestServer) trusted(command string, extra ...string) []string {
	return s.args(command, append([]string{"--ca-cert", s.caFile}, extra...)...)
}

// scepRequests lists the message type or operation of every request in the exchange.
func scepRequests(doc map[string]any) string {
	events, _ := doc["exchange"].([]any)
	var ops []string
	for _, ev := range events {
		if get(ev, "kind") == "request" {
			op := text(get(ev, "messageType"))
			if op == "" {
				op = text(get(ev, "operation"))
			}
			ops = append(ops, op)
		}
	}
	return strings.Join(ops, " ")
}

// TestSCEPCaps checks the capabilities report and the choices go-scep makes from them.
func TestSCEPCaps(t *testing.T) {
	useChallenge(t, "")
	srv := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, nil)
	code, doc := runJSON(t, srv.args("caps")...)
	if code != exitOK || get(doc, "result.digest") != "SHA-256" || get(doc, "result.cipher") != "AES-128-CBC" ||
		get(doc, "result.method") != "POST" || get(doc, "result.renewal") != true || get(doc, "result.nextCACert") != false {
		t.Errorf("default capabilities: exit %d, result %v", code, doc["result"])
	}
	old := startSCEPServer(t, scepca.Options{}, scepserver.Options{Capabilities: []string{"SHA-1", "DES3"}}, nil)
	code, doc = runJSON(t, old.args("caps")...)
	if code != exitOK || get(doc, "result.digest") != "SHA-1" || get(doc, "result.cipher") != "DES-EDE3-CBC" ||
		get(doc, "result.method") != "GET" || get(doc, "result.renewal") != false {
		t.Errorf("old capabilities: exit %d, result %v", code, doc["result"])
	}
}

// TestSCEPCACert checks GetCACert with SHA-256 and SHA-1 fingerprints, an RA and a wrong fingerprint.
func TestSCEPCACert(t *testing.T) {
	useChallenge(t, "")
	srv := startSCEPServer(t, scepca.Options{RA: true, Name: "Issuing"}, scepserver.Options{}, nil)
	sum256 := sha256.Sum256(srv.ca.Certificate().Raw)
	sum1 := sha1.Sum(srv.ca.Certificate().Raw) //nolint:gosec // G401: SCEP fingerprints may be SHA-1.

	code, doc := runJSON(t, srv.args("cacert", "--ca", "Issuing")...)
	if code != exitOK || get(doc, "result.verified") != verifiedNone || len(get(doc, "result.certificates").([]any)) != 2 {
		t.Fatalf("cacert: exit %d, result %v", code, doc["result"])
	}
	if roles := get(doc, "result.certificates.1.roles"); text(get(roles, "0")) != "RA encryption" {
		t.Errorf("RA roles %v", roles)
	}

	for name, fp := range map[string]string{"SHA-256": hex.EncodeToString(sum256[:]), "SHA-1": strings.ToUpper(hex.EncodeToString(sum1[:]))} {
		out := filepath.Join(t.TempDir(), "ca.pem")
		code, doc := runJSON(t, srv.args("cacert", "--ca", "Issuing", "--fingerprint", fp, "--out", out)...)
		if code != exitOK || get(doc, "result.verified") != verifiedFingerprint {
			t.Errorf("%s fingerprint: exit %d, result %v, error %v", name, code, doc["result"], doc["error"])
			continue
		}
		certs, err := pemfile.ReadCertificates(out)
		if err != nil || len(certs) != 2 || !certs[0].Equal(srv.ca.Certificate()) {
			t.Errorf("%s fingerprint saved %d certificates: %v", name, len(certs), err)
		}
	}

	wrong := strings.Repeat("ab", 32)
	code, doc = runJSON(t, srv.args("cacert", "--ca", "Issuing", "--fingerprint", wrong, "--out", filepath.Join(t.TempDir(), "x.pem"))...)
	if code != exitProtocol || get(doc, "error.hint") != hintCheckFingerprint {
		t.Errorf("wrong fingerprint: exit %d, error %v", code, doc["error"])
	}

	code, doc = runJSON(t, srv.args("cacert", "--ca", "Other")...)
	if code != exitTransport || !strings.Contains(text(get(doc, "error.hint")), "the name of the CA in --ca") {
		t.Errorf("unknown CA name: exit %d, error %v", code, doc["error"])
	}
}

// TestSCEPChainAndNextCA checks GetCACertChain and GetNextCACert, with and without a next CA.
func TestSCEPChainAndNextCA(t *testing.T) {
	useChallenge(t, "")
	srv := startSCEPServer(t, scepca.Options{NextCA: true}, scepserver.Options{}, nil)
	code, doc := runJSON(t, srv.args("chain")...)
	if code != exitOK || len(get(doc, "result.certificates").([]any)) != 2 ||
		get(doc, "result.certificates.1.subject") != "CN=certrally SCEP Mock Root CA" {
		t.Errorf("chain: exit %d, result %v", code, doc["result"])
	}
	out := filepath.Join(t.TempDir(), "next.pem")
	code, doc = runJSON(t, srv.trusted("nextca", "--out", out)...)
	if code != exitOK || get(doc, "result.verified") != verifiedSigned {
		t.Fatalf("nextca: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	if next := readCert(t, out); next.Equal(srv.ca.Certificate()) || next.CheckSignatureFrom(srv.ca.Root()) != nil {
		t.Errorf("next CA certificate %s is not a new certificate of the root", next.Subject)
	}

	// A CA without a rollover may answer 501, or 200 with an empty body.
	plain := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, nil)
	code, doc = runJSON(t, plain.trusted("nextca")...)
	if code != exitRejected || get(doc, "error.httpStatus") != float64(http.StatusNotImplemented) {
		t.Errorf("nextca without the operation: exit %d, error %v", code, doc["error"])
	}
	empty := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("operation") == "GetNextCACert" {
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	code, doc = runJSON(t, empty.trusted("nextca")...)
	if code != exitOK || len(get(doc, "result.certificates").([]any)) != 0 {
		t.Errorf("nextca with an empty answer: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
}

// TestSCEPEnroll checks enrollment with RSA and ECDSA keys, legacy algorithms and a wrong challenge.
func TestSCEPEnroll(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{Challenge: []byte(scepTestChallenge)}, scepserver.Options{AllowMD5: true}, nil)
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=dev-1,O=Example", "--san", "dns:dev-1.example.com",
		"--cert-out", certOut, "--key-out", keyOut)...)
	if code != exitOK {
		t.Fatalf("scep enroll exited with %d: %v", code, doc["error"])
	}
	cert := readCert(t, certOut)
	if cert.Subject.CommonName != "dev-1" || len(cert.DNSNames) != 1 || cert.CheckSignatureFrom(srv.ca.Certificate()) != nil {
		t.Errorf("certificate %s with %v", cert.Subject, cert.DNSNames)
	}
	// --ca-cert skips GetCACert.
	if got := scepRequests(doc); got != "GetCACaps PKCSReq" {
		t.Errorf("requests %q, want GetCACaps PKCSReq", got)
	}
	tid := text(get(doc, "result.transactionId"))
	if get(doc, "result.status") != "SUCCESS" || len(tid) != 40 || strings.ToUpper(tid) != tid ||
		get(doc, "result.digest") != "sha256" || get(doc, "result.key") != "RSA 2048" {
		t.Errorf("result %v", doc["result"])
	}
	if info, err := os.Stat(keyOut); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v", info, err)
	}
	if _, err := os.Stat(certOut + ".state"); !os.IsNotExist(err) {
		t.Error("a successful enrollment left a state file")
	}

	t.Run("ECDSA key and legacy algorithms", func(t *testing.T) {
		certOut := filepath.Join(t.TempDir(), "ec.pem")
		code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=ec", "--key-type", "ecdsa-p256", "--hash", "sha1",
			"--cipher", "des3", "--cert-out", certOut, "--key-out", filepath.Join(t.TempDir(), "ec.key"))...)
		if code != exitOK {
			t.Fatalf("exit %d: %v", code, doc["error"])
		}
		if _, ok := readCert(t, certOut).PublicKey.(*ecdsa.PublicKey); !ok {
			t.Error("the certificate does not certify the ECDSA key")
		}
		if get(doc, "result.digest") != "sha1" || get(doc, "result.cipher") != "des3" {
			t.Errorf("result %v", doc["result"])
		}
	})

	t.Run("MD5", func(t *testing.T) {
		code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=md5", "--hash", "md5",
			"--cert-out", filepath.Join(t.TempDir(), "md5.pem"), "--key-out", filepath.Join(t.TempDir(), "md5.key"))...)
		if code != exitOK || get(doc, "result.digest") != "md5" {
			t.Errorf("exit %d, result %v, error %v", code, doc["result"], doc["error"])
		}
	})

	t.Run("wrong challenge", func(t *testing.T) {
		challengeFile := filepath.Join(t.TempDir(), "challenge.txt")
		writeFile(t, challengeFile, []byte("wrong\n"))
		code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=bad", "--challenge-file", challengeFile,
			"--cert-out", filepath.Join(t.TempDir(), "bad.pem"), "--key-out", filepath.Join(t.TempDir(), "bad.key"))...)
		if code != exitRejected || get(doc, "error.status") != "FAILURE" || text(get(doc, "error.failInfo.0")) != "badRequest" ||
			!strings.Contains(text(get(doc, "error.hint")), "challenge password") {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
	})
}

// TestSCEPCSRDigest checks that --hash also selects the digest of the PKCS#10 signature, with and
// without a challenge password. MD5, which crypto/x509 does not sign with, keeps the default.
func TestSCEPCSRDigest(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		key       crypto.Signer
		digest    crypto.Hash
		challenge string
		want      x509.SignatureAlgorithm
	}{
		{"RSA SHA-1", rsaKey, crypto.SHA1, "pw", x509.SHA1WithRSA},
		{"RSA SHA-1 without challenge", rsaKey, crypto.SHA1, "", x509.SHA1WithRSA},
		{"ECDSA SHA-1", p384, crypto.SHA1, "pw", x509.ECDSAWithSHA1},
		{"RSA SHA-512", rsaKey, crypto.SHA512, "pw", x509.SHA512WithRSA},
		{"RSA MD5", rsaKey, crypto.MD5, "pw", x509.SHA256WithRSA},
		{"ECDSA P-384 default", p384, 0, "pw", x509.ECDSAWithSHA384},
	}
	o := &scepEnrollOptions{subject: "CN=device"}
	for _, tt := range tests {
		csr, err := o.createCSR(tt.key, nil, tt.challenge, tt.digest)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if csr.SignatureAlgorithm != tt.want || csr.CheckSignature() != nil {
			t.Errorf("%s: signed with %s, want %s, check %v", tt.name, csr.SignatureAlgorithm, tt.want, csr.CheckSignature())
		}
	}
}

// TestSCEPRenewAndQueries checks RenewalReq, GetCert and GetCRL with a certificate the CA issued.
func TestSCEPRenewAndQueries(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{Challenge: []byte(scepTestChallenge)}, scepserver.Options{}, nil)
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=dev", "--san", "dns:dev.example.com",
		"--cert-out", certOut, "--key-out", keyOut)...); code != exitOK {
		t.Fatalf("enroll exited with %d: %v", code, doc["error"])
	}
	cert := readCert(t, certOut)
	useChallenge(t, "")

	renewed := filepath.Join(dir, "renewed.pem")
	code, doc := runJSON(t, srv.trusted("renew", "--cert", certOut, "--key", keyOut, "--cert-out", renewed,
		"--key-out", filepath.Join(dir, "renewed.key"))...)
	if code != exitOK || get(doc, "result.messageType") != "RenewalReq" {
		t.Fatalf("renew: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	if r := readCert(t, renewed); !bytes.Equal(r.RawSubject, cert.RawSubject) || len(r.DNSNames) != 1 ||
		bytes.Equal(r.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		t.Errorf("renewed %s with %v", r.Subject, r.DNSNames)
	}

	found := filepath.Join(dir, "found.pem")
	code, doc = runJSON(t, srv.trusted("getcert", "--serial", "0x"+cert.SerialNumber.Text(16), "--cert", certOut,
		"--key", keyOut, "--out", found)...)
	if code != exitOK || !readCert(t, found).Equal(cert) {
		t.Errorf("getcert: exit %d, error %v", code, doc["error"])
	}
	code, doc = runJSON(t, srv.trusted("getcert", "--serial", "42")...)
	if code != exitRejected || text(get(doc, "error.failInfo.0")) != "badCertId" {
		t.Errorf("getcert of an unknown serial: exit %d, error %v", code, doc["error"])
	}
	crlOut := filepath.Join(dir, "ca.crl")
	code, doc = runJSON(t, srv.trusted("getcrl", "--cert", certOut, "--key", keyOut, "--out", crlOut)...)
	if code != exitOK {
		t.Errorf("getcrl: exit %d, error %v", code, doc["error"])
	}
	if _, err := os.Stat(crlOut); err != nil {
		t.Errorf("getcrl saved no CRL: %v", err)
	}
}

// TestSCEPPending checks --poll-later, the state file, scep poll and polling within --timeout.
func TestSCEPPending(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{PendingPolls: 2}, scepserver.Options{}, nil)
	dir := t.TempDir()
	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	state := certOut + ".state"
	code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=pending", "--poll-later",
		"--cert-out", certOut, "--key-out", keyOut)...)
	if code != exitOK || get(doc, "result.status") != "PENDING" || get(doc, "result.state") == nil {
		t.Fatalf("enroll --poll-later: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	info, err := os.Stat(state)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v, %v", info, err)
	}
	if _, err := os.Stat(keyOut); err != nil {
		t.Errorf("the key of the pending request was not saved: %v", err)
	}
	if bytes.Contains(readFile(t, state), []byte(scepTestChallenge)) {
		t.Error("the state file holds the challenge password")
	}

	useChallenge(t, "")
	code, doc = runJSON(t, "scep", "poll", "--state", state, "--once")
	if code != exitOK || get(doc, "result.status") != "PENDING" || get(doc, "result.polls") != float64(1) {
		t.Fatalf("poll --once: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	code, doc = runJSON(t, "scep", "poll", "--state", state, "--poll-interval", "10ms")
	if code != exitOK || get(doc, "result.status") != "SUCCESS" {
		t.Fatalf("poll: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Error("the state file was kept after the certificate was issued")
	}
	if cert := readCert(t, certOut); cert.Subject.CommonName != "pending" {
		t.Errorf("collected %s", cert.Subject)
	}

	t.Run("wait", func(t *testing.T) {
		useChallenge(t, scepTestChallenge)
		code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=wait", "--poll-interval", "10ms",
			"--cert-out", filepath.Join(t.TempDir(), "wait.pem"), "--key-out", filepath.Join(t.TempDir(), "wait.key"))...)
		if code != exitOK || get(doc, "result.polls") != float64(2) || scepRequests(doc) != "GetCACaps PKCSReq CertPoll CertPoll" {
			t.Errorf("exit %d, requests %q, result %v", code, scepRequests(doc), doc["result"])
		}
	})

	t.Run("timeout", func(t *testing.T) {
		useChallenge(t, scepTestChallenge)
		slow := startSCEPServer(t, scepca.Options{PendingPolls: 1000}, scepserver.Options{}, nil)
		certOut := filepath.Join(t.TempDir(), "slow.pem")
		code, doc := runJSON(t, slow.trusted("enroll", "--subject", "CN=slow", "--poll-interval", "100ms", "--timeout", "1s",
			"--cert-out", certOut, "--key-out", filepath.Join(t.TempDir(), "slow.key"))...)
		if code != exitTransport || !strings.Contains(text(get(doc, "error.title")), "not decided") {
			t.Errorf("exit %d, error %v", code, doc["error"])
		}
		if _, err := os.Stat(certOut + ".state"); err != nil {
			t.Errorf("the timed-out request has no state file: %v", err)
		}
	})
}

// TestSCEPBusy checks that a 503 answer without Retry-After is retried after --busy-wait, and that
// --busy-retries 0 reports it.
func TestSCEPBusy(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{PendingPolls: 1, BusyInterval: 300 * time.Millisecond}, scepserver.Options{}, nil)
	code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=busy", "--poll-interval", "10ms", "--busy-wait", "400ms",
		"--cert-out", filepath.Join(t.TempDir(), "busy.pem"), "--key-out", filepath.Join(t.TempDir(), "busy.key"))...)
	if code != exitOK || scepRequests(doc) != "GetCACaps PKCSReq CertPoll CertPoll" {
		t.Errorf("busy retry: exit %d, requests %q, error %v", code, scepRequests(doc), doc["error"])
	}

	time.Sleep(400 * time.Millisecond)
	code, doc = runJSON(t, srv.trusted("enroll", "--subject", "CN=busy2", "--poll-interval", "10ms", "--busy-retries", "0",
		"--cert-out", filepath.Join(t.TempDir(), "busy2.pem"), "--key-out", filepath.Join(t.TempDir(), "busy2.key"))...)
	if code != exitRejected || get(doc, "error.httpStatus") != float64(http.StatusServiceUnavailable) ||
		!strings.Contains(text(get(doc, "error.hint")), "--busy-retries") {
		t.Errorf("no retries: exit %d, error %v", code, doc["error"])
	}
}

// TestSCEPAllowDES checks that an answer encrypted with single DES is refused with a hint, accepted
// with --allow-des and that scep poll keeps the choice of the enrollment.
func TestSCEPAllowDES(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{}, scepserver.Options{ContentEncryption: pkcs7.DESCBC}, nil)
	dir := t.TempDir()
	code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=des", "--cert-out", filepath.Join(dir, "refused.pem"),
		"--key-out", filepath.Join(dir, "refused.key"))...)
	if code != exitProtocol || !strings.Contains(text(get(doc, "error.hint")), "--allow-des") {
		t.Errorf("DES answer without --allow-des: exit %d, error %v", code, doc["error"])
	}
	code, doc = runJSON(t, srv.trusted("enroll", "--subject", "CN=des", "--allow-des", "--cert-out", filepath.Join(dir, "des.pem"),
		"--key-out", filepath.Join(dir, "des.key"))...)
	if code != exitOK {
		t.Errorf("DES answer with --allow-des: exit %d, error %v", code, doc["error"])
	}

	pending := startSCEPServer(t, scepca.Options{PendingPolls: 1}, scepserver.Options{ContentEncryption: pkcs7.DESCBC}, nil)
	certOut := filepath.Join(dir, "pending.pem")
	code, doc = runJSON(t, pending.trusted("enroll", "--subject", "CN=des-pending", "--allow-des", "--poll-later",
		"--cert-out", certOut, "--key-out", filepath.Join(dir, "pending.key"))...)
	if code != exitOK || get(doc, "result.status") != "PENDING" {
		t.Fatalf("pending enroll: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
	useChallenge(t, "")
	if code, doc = runJSON(t, "scep", "poll", "--state", certOut+".state"); code != exitOK {
		t.Errorf("poll of a request sent with --allow-des: exit %d, error %v", code, doc["error"])
	}
}

// nulCapsHandler answers GetCACaps with a trailing NUL byte and GetCACert without a CA name with an
// empty body, as some CA products do.
func nulCapsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("operation") == "GetCACaps":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Renewal\nSHA-1\nSHA-256\nAES\n\x00"))
		case q.Get("operation") == "GetCACert" && q.Get("message") == "":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// TestSCEPQuirks checks the reports for a CA that needs its name and lists its capabilities with a
// NUL byte.
func TestSCEPQuirks(t *testing.T) {
	useChallenge(t, "")
	srv := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, nulCapsHandler)
	code, doc := runJSON(t, srv.args("cacert")...)
	if code != exitTransport || !strings.Contains(text(get(doc, "error.hint")), "name of the CA in --ca") {
		t.Errorf("empty GetCACert: exit %d, error %v", code, doc["error"])
	}
	code, doc = runJSON(t, srv.args("caps")...)
	if code != exitOK || !hasWarning(doc, "NUL byte") || len(get(doc, "result.capabilities").([]any)) != 4 {
		t.Errorf("NUL in caps: exit %d, warnings %v, result %v", code, doc["warnings"], doc["result"])
	}
	code, doc = runJSON(t, srv.args("caps", "--profile", "strict")...)
	if code != exitProfile {
		t.Errorf("NUL in caps with the strict profile: exit %d, error %v", code, doc["error"])
	}
}

// TestSCEPEmptyPKIOperation checks the hints for a server that answers a PKIOperation without
// content, as some do for a message type they do not support.
func TestSCEPEmptyPKIOperation(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	var empty atomic.Bool
	srv := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if empty.Load() && r.URL.Query().Get("operation") == "PKIOperation" {
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "device.pem"), filepath.Join(dir, "device.key")
	if code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=device", "--cert-out", cert, "--key-out", key)...); code != exitOK {
		t.Fatalf("enroll: exit %d, error %v", code, doc["error"])
	}
	empty.Store(true)
	tests := []struct {
		name string
		args []string
		hint string
	}{
		{"PKCSReq", srv.trusted("enroll", "--subject", "CN=again", "--cert-out", filepath.Join(dir, "again.pem"),
			"--key-out", filepath.Join(dir, "again.key")), "name of the CA in --ca"},
		{"RenewalReq", srv.trusted("renew", "--cert", cert, "--key", key, "--cert-out", filepath.Join(dir, "renewed.pem"),
			"--key-out", filepath.Join(dir, "renewed.key")), "may not support RenewalReq"},
		{"GetCert", srv.trusted("getcert", "--cert", cert, "--key", key, "--serial", "1"), "may not support GetCert"},
		{"GetCRL", srv.trusted("getcrl", "--cert", cert, "--key", key), "may not support GetCRL"},
	}
	for _, tt := range tests {
		code, doc := runJSON(t, tt.args...)
		if code != exitTransport || !strings.Contains(text(get(doc, "error.hint")), tt.hint) {
			t.Errorf("%s: exit %d, error %v", tt.name, code, doc["error"])
		}
	}
}

// pkiStatusAsHTTPStatus answers a PENDING CertRep with HTTP 202 and a FAILURE CertRep with HTTP
// 400, as some CA products do.
func pkiStatusAsHTTPStatus(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		status := rec.Code
		if r.URL.Query().Get("operation") == trace.SCEPPKIOperation && status == http.StatusOK {
			summary, _ := trace.SummarizeSCEPResponse(trace.SCEPPKIOperation, rec.Result(), rec.Body.Bytes())
			switch summary.Status {
			case trace.SCEPPending:
				status = http.StatusAccepted
			case trace.SCEPFailure:
				status = http.StatusBadRequest
			}
		}
		maps.Copy(w.Header(), rec.Header())
		w.WriteHeader(status)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

// lastSCEPResponse returns the last response of the exchange.
func lastSCEPResponse(doc map[string]any) any {
	events, _ := doc["exchange"].([]any)
	for _, ev := range slices.Backward(events) {
		if get(ev, "kind") == "response" {
			return ev
		}
	}
	return nil
}

// TestSCEPCertRepWithErrorStatus checks enrollment, a refusal, inspect and lint against a server
// that sends PENDING and FAILURE CertReps with HTTP 202 and 400.
func TestSCEPCertRepWithErrorStatus(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{Challenge: []byte(scepTestChallenge), PendingPolls: 1}, scepserver.Options{},
		pkiStatusAsHTTPStatus)
	dir := t.TempDir()
	capture := filepath.Join(dir, "run.jsonl")
	code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=accepted", "--poll-later", "--capture", capture,
		"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))...)
	resp := lastSCEPResponse(doc)
	if code != exitOK || get(doc, "result.status") != "PENDING" || get(resp, "httpStatus") != float64(http.StatusAccepted) ||
		get(resp, "messageType") != "CertRep" || get(resp, "status") != "PENDING" {
		t.Fatalf("enroll: exit %d, response %v, error %v", code, resp, doc["error"])
	}
	if code, doc := runJSON(t, "scep", "poll", "--state", filepath.Join(dir, "cert.pem.state")); code != exitOK {
		t.Fatalf("poll: exit %d, error %v", code, doc["error"])
	}

	wrong := filepath.Join(dir, "wrong.txt")
	writeFile(t, wrong, []byte("wrong\n"))
	refused := srv.trusted("enroll", "--subject", "CN=refused", "--challenge-file", wrong, "--capture", capture,
		"--cert-out", filepath.Join(dir, "refused.pem"), "--key-out", filepath.Join(dir, "refused.key"))
	code, doc = runJSON(t, refused...)
	resp = lastSCEPResponse(doc)
	if code != exitRejected || get(doc, "error.status") != "FAILURE" || text(get(doc, "error.failInfo.0")) != "badRequest" ||
		get(resp, "httpStatus") != float64(http.StatusBadRequest) || get(resp, "status") != "FAILURE" {
		t.Errorf("wrong challenge: exit %d, response %v, error %v", code, resp, doc["error"])
	}
	code, stdout, stderr := run(t, refused...)
	if code != exitRejected || !strings.Contains(removeSpace(stdout+stderr), "CertRepFAILUREbadRequestHTTP400") {
		t.Errorf("ladder of the refusal: exit %d\n%s%s", code, stdout, stderr)
	}

	code, doc = runJSON(t, "inspect", capture)
	messages, _ := get(doc, "result.messages").([]any)
	var pending, failure bool
	for _, m := range messages {
		pending = pending || (get(m, "scep.httpStatus") == float64(http.StatusAccepted) && get(m, "scep.status") == "PENDING")
		failure = failure || (get(m, "scep.httpStatus") == float64(http.StatusBadRequest) && get(m, "scep.failInfo") == "badRequest")
	}
	if code != exitOK || !pending || !failure {
		t.Errorf("inspect: exit %d, PENDING with HTTP 202 %v, FAILURE with HTTP 400 %v", code, pending, failure)
	}
	if code, doc := runJSON(t, "lint", capture); code != exitOK {
		t.Errorf("lint: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
}

// TestSCEPBadCertIDHint checks that the badCertId hint names what identifies the certificate in the
// failed message.
func TestSCEPBadCertIDHint(t *testing.T) {
	tests := []struct{ messageType, want, not string }{
		{"RenewalReq", "--cert", "--serial"},
		{"GetCert", "--serial", ""},
		{"GetCRL", "--cert", ""},
		{"CertPoll", "pending request", "--serial"},
	}
	for _, tt := range tests {
		hint := scepFailInfoHint("badCertId", tt.messageType)
		if !strings.Contains(hint, tt.want) || (tt.not != "" && strings.Contains(hint, tt.not)) {
			t.Errorf("%s: hint %q", tt.messageType, hint)
		}
	}
}

// TestSCEPEnrollRefused checks the hint and the server text when a server refuses a PKCSReq with an
// HTTP error and an HTML or plain text page.
func TestSCEPEnrollRefused(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	tests := []struct {
		name, contentType, body, text string
		status                        int
	}{
		{"html", "text/html;charset=UTF-8", "<html><head><title>Error</title></head><body>No password in request.</body></html>",
			"No password in request.", http.StatusBadRequest},
		{"text", "text/plain", "Wrong username or password", "Wrong username or password", http.StatusUnauthorized},
		{"forbidden", "text/html", "<html><body>User device not found.</body></html>", "User device not found.", http.StatusForbidden},
	}
	for _, tt := range tests {
		srv := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("operation") != trace.SCEPPKIOperation {
					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
		})
		code, doc := runJSON(t, srv.trusted("enroll", "--subject", "CN=device", "--cert-out", filepath.Join(t.TempDir(), "device.pem"),
			"--key-out", filepath.Join(t.TempDir(), "device.key"))...)
		if code != exitRejected || get(doc, "error.statusText.0") != tt.text ||
			!strings.Contains(text(get(doc, "error.hint")), "challenge password") {
			t.Errorf("%s: exit %d, error %v", tt.name, code, doc["error"])
		}
	}
}

// TestSCEPCaptureInspectAndLint checks that a capture of a SCEP enrollment can be inspected and
// linted.
func TestSCEPCaptureInspectAndLint(t *testing.T) {
	useChallenge(t, scepTestChallenge)
	srv := startSCEPServer(t, scepca.Options{}, scepserver.Options{}, nulCapsHandler)
	dir := t.TempDir()
	capture := filepath.Join(dir, "run.jsonl")
	code, doc := runJSON(t, srv.args("enroll", "--ca", "Issuing", "--subject", "CN=cap", "--capture", capture,
		"--cert-out", filepath.Join(dir, "cap.pem"), "--key-out", filepath.Join(dir, "cap.key"))...)
	if code != exitOK {
		t.Fatalf("enroll exited with %d: %v", code, doc["error"])
	}
	var start struct {
		Protocol string `json:"protocol"`
	}
	firstLine, _, _ := bytes.Cut(readFile(t, capture), []byte("\n"))
	if err := json.Unmarshal(firstLine, &start); err != nil || start.Protocol != protocolSCEP {
		t.Fatalf("start line %s: %v", firstLine, err)
	}

	code, doc = runJSON(t, "inspect", capture)
	messages, _ := get(doc, "result.messages").([]any)
	if code != exitOK || len(messages) != 6 {
		t.Fatalf("inspect: exit %d, %d messages", code, len(messages))
	}
	req, resp := messages[4], messages[5]
	if get(req, "protocol") != protocolSCEP || get(req, "scep.messageType") != "PKCSReq" || get(req, "certificates.0") == nil {
		t.Errorf("request: %v", req)
	}
	if get(resp, "scep.status") != "SUCCESS" || get(resp, "scep.recipientNonce") != get(req, "scep.senderNonce") {
		t.Errorf("response: %v", resp)
	}
	if get(messages[3], "certificates.0.subject") != "CN=certrally SCEP Mock CA" {
		t.Errorf("GetCACert answer: %v", messages[3])
	}

	code, doc = runJSON(t, "lint", capture)
	if code != exitProfile || !strings.Contains(text(get(doc, "error.message")), "RFC 8894") ||
		!strings.Contains(text(get(doc, "result.findings.0.text")), "NUL byte") {
		t.Errorf("lint: exit %d, result %v, error %v", code, doc["result"], doc["error"])
	}
}

// readFile returns the content of path.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test names the file.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// scepMockServerURL is the address in the startup report of scep mock.
var scepMockServerURL = regexp.MustCompile(`Server\s+(http://\S+)`)

// startSCEPMock runs scep mock with args until the test ends or stop is called.
func startSCEPMock(t *testing.T, args ...string) *mockRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &mockRun{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() { m.done <- Run(ctx, append([]string{"scep", "mock"}, args...), m.stdout, m.stderr) }()
	t.Cleanup(func() {
		cancel()
		<-m.done
	})
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(m.stdout.String(), "Press Ctrl-C to stop.") {
		select {
		case code := <-m.done:
			m.done <- code
			t.Fatalf("scep mock exited with %d before it was ready:\n%s%s", code, m.stdout, m.stderr)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("scep mock did not start:\n%s%s", m.stdout, m.stderr)
		}
	}
	match := scepMockServerURL.FindStringSubmatch(m.stdout.String())
	if match == nil {
		t.Fatalf("startup report lacks the server URL:\n%s", m.stdout)
	}
	m.url = match[1]
	return m
}

// TestSCEPMock checks scep mock: its startup report, an enrollment, a refusal and the request log.
func TestSCEPMock(t *testing.T) {
	useChallenge(t, "")
	dir := t.TempDir()
	challengeFile, caOut := filepath.Join(dir, "challenge.txt"), filepath.Join(dir, "ca.pem")
	writeFile(t, challengeFile, []byte(scepTestChallenge+"\n"))
	m := startSCEPMock(t, "--listen", "127.0.0.1:0", "--ca-name", "Mock CA", "--challenge-file", challengeFile, "--ca-out", caOut)
	caCert := readCert(t, caOut)
	sum := sha256.Sum256(caCert.Raw)
	report := m.stdout.String()
	for _, want := range []string{hex.EncodeToString(sum[:]), "--ca 'Mock CA' --ca-cert " + caOut, "--challenge-file " + challengeFile} {
		if !strings.Contains(report, want) {
			t.Errorf("startup report lacks %q:\n%s", want, report)
		}
	}

	code, doc := runJSON(t, "scep", "enroll", "--server", m.url, "--ca", "Mock CA", "--ca-cert", caOut, "--challenge-file", challengeFile,
		"--subject", "CN=mock", "--cert-out", filepath.Join(dir, "mock.pem"), "--key-out", filepath.Join(dir, "mock.key"))
	if code != exitOK {
		t.Errorf("enroll: exit %d, error %v", code, doc["error"])
	}
	code, doc = runJSON(t, "scep", "enroll", "--server", m.url, "--ca", "Mock CA", "--ca-cert", caOut, "--challenge", "wrong",
		"--subject", "CN=bad", "--cert-out", filepath.Join(dir, "bad.pem"), "--key-out", filepath.Join(dir, "bad.key"))
	if code != exitRejected {
		t.Errorf("wrong challenge: exit %d, error %v", code, doc["error"])
	}

	if code := m.stop(t); code != exitOK {
		t.Errorf("scep mock exited with %d:\n%s", code, m.stderr)
	}
	output := m.stdout.String()
	for _, want := range []string{"POST  PKCSReq  SHA-256  ->  HTTP 200  CertRep  SUCCESS", "CertRep  FAILURE  badRequest",
		"wrong challenge password", "Mock CA stopped"} {
		if !strings.Contains(output, want) {
			t.Errorf("log lacks %q:\n%s", want, output)
		}
	}
}

// TestSCEPMockErrors checks that scep mock refuses bad settings and leaves no CA file behind.
func TestSCEPMockErrors(t *testing.T) {
	useChallenge(t, "")
	dir := t.TempDir()
	caOut, empty := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "empty.txt")
	writeFile(t, empty, nil)
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--pending-polls", "-1"}, "--pending-polls must not be negative"},
		{[]string{"--busy-interval", "-1s"}, "--busy-interval must not be negative"},
		{[]string{"--challenge", "x", "--any-challenge"}, "none of the others can be"},
		{[]string{"--listen", "127.0.0.1:99999", "--any-challenge", "--ca-out", caOut}, "--listen"},
	}
	for _, tt := range tests {
		code, _, errOut := run(t, append([]string{"scep", "mock"}, tt.args...)...)
		if code != exitLocal || !errorContains(errOut, tt.want) {
			t.Errorf("%q: exit %d:\n%s", tt.args, code, errOut)
		}
	}
	if _, err := os.Stat(caOut); !os.IsNotExist(err) {
		t.Error("a failed start left the CA file")
	}
}

// TestSCEPUsageErrors checks flag combinations that the SCEP commands refuse before connecting.
func TestSCEPUsageErrors(t *testing.T) {
	useChallenge(t, "")
	dir := t.TempDir()
	csrFile := filepath.Join(dir, "req.csr")
	writeFile(t, csrFile, []byte("not used"))
	server := "http://scep.example.com/scep"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"scep", "caps", "--server", server + "?operation=GetCACaps"}, "query"},
		{[]string{"scep", "caps", "--server", "http://user:pw@scep.example.com/scep"}, "user"},
		{[]string{"scep", "caps", "--server", server, "--proxy", "ftp://proxy:21"}, "--proxy"},
		{[]string{"scep", "cacert", "--server", server, "--fingerprint", "abcd"}, "--fingerprint"},
		{[]string{"scep", "enroll", "--server", server, "--cert-out", "x.pem", "--hash", "sha3"}, "--hash"},
		{[]string{"scep", "enroll", "--server", server, "--cert-out", "x.pem", "--cipher", "rc2"}, "--cipher"},
		{[]string{"scep", "enroll", "--server", server, "--cert-out", "x.pem", "--csr", csrFile, "--challenge", "x"},
			"a challenge password cannot be added to a request given with --csr"},
		{[]string{"scep", "enroll", "--server", server, "--cert-out", "x.pem", "--subject", "CN=x", "--key-type", "ed25519"}, "--key-type"},
		{[]string{"scep", "renew", "--server", server, "--cert-out", "x.pem"}, "required flag"},
		{[]string{"scep", "getcrl", "--server", server}, "--serial or --cert names the certificate"},
		{[]string{"scep", "getcert", "--server", server, "--serial", "1", "--cert", "c.pem"}, "if any flags in the group"},
		{[]string{"scep", "getcrl", "--server", server, "--issuer", "CN=x", "--cert", "c.pem", "--key", "k.pem"}, "--issuer needs --serial"},
		{[]string{"scep", "poll", "--state", filepath.Join(dir, "missing.state")}, "missing.state"},
	}
	for _, tt := range tests {
		code, _, errOut := run(t, tt.args...)
		if code != exitLocal || !errorContains(errOut, tt.want) {
			t.Errorf("%q: exit %d, want %q:\n%s", tt.args, code, tt.want, errOut)
		}
	}

	bad := filepath.Join(dir, "bad.state")
	writeFile(t, bad, []byte(`{"version": 99}`))
	if code, _, errOut := run(t, "scep", "poll", "--state", bad); code != exitLocal || !errorContains(errOut, "state version 99") {
		t.Errorf("state of another version: exit %d:\n%s", code, errOut)
	}
}
