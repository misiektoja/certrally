//go:build integration

// Package libest runs the EST commands of certrally against the example server of Cisco libest,
// built from the Dockerfile in this directory.
package libest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/certrally/test/integration/internal/itest"
)

const (
	// The example server code accepts this user and password for HTTP authentication.
	estUser     = "estuser"
	estPassword = "estpwd"
	// The Dockerfile writes a TLS-SRP verifier for this user and password.
	srpUser     = "srpuser"
	srpPassword = "srppwd"
	// csrAttrs are the CSR attributes of the runserver.sh example of libest in base64.
	csrAttrs = "MGwGBysGAQEBARYwIgYDiDcBMRsTGVBhcnNlIFNFVCBhcyAyLjk5OS4xIGRhdGEwJwYDiDcCMSAGA4g3AxMZUGFyc2UgU0VUIGFzIDIuOTk5LjIgZGF0YQYJKyQDAwIIAQELBglghkgBZQMEAgI="
	// dockerTimeout limits one docker command.
	dockerTimeout = time.Minute
)

// TestLibest runs each EST operation against two example servers. One accepts TLS client
// certificates without HTTP authentication and TLS-SRP, the other requires the tls-unique binding.
func TestLibest(t *testing.T) {
	c := itest.New(t)
	ca := docker(t, "run", "--rm", "--entrypoint", "cat", image(), "estCA/cacert.crt")
	c.WriteFile(t, "ca.pem", ca)
	c.WriteFile(t, "estpwd", []byte(estPassword+"\n"))
	c.WriteFile(t, "srppwd", []byte(srpPassword+"\n"))
	caCert := c.Certificates(t, "ca.pem")[0]
	fingerprint := sha256.Sum256(caCert.Raw)

	open := startServer(t, caCert, []string{"EST_CSR_ATTR=" + csrAttrs}, "-o", "--srp", "certrally.srpv")
	bound := startServer(t, caCert, nil, "-t")
	password := []string{"--user", estUser, "--password-file", "estpwd"}
	// subject names a certificate after the step that requests it.
	subject := func(t *testing.T) string { return "CN=certrally-libest-" + strings.ReplaceAll(t.Name(), "/", "-") }

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"cacerts", func(t *testing.T) {
			c.Expect(t, 0, "est", "cacerts", "--server", open, "--tls-ca-cert", "ca.pem", "--out", "cacerts.pem", "--capture", "est.jsonl")
			requireSame(t, c, "cacerts.pem", caCert)
		}},
		{"cacerts-bootstrap", func(t *testing.T) {
			c.Expect(t, 0, "est", "cacerts", "--server", open, "--bootstrap", "--fingerprint", hex.EncodeToString(fingerprint[:]),
				"--out", "bootstrap.pem", "--capture", "est.jsonl")
			requireSame(t, c, "bootstrap.pem", caCert)
		}},
		{"csrattrs", func(t *testing.T) {
			c.ExpectOutput(t, 0, "The CA asks for 5 attributes",
				append([]string{"est", "csrattrs", "--server", open, "--tls-ca-cert", "ca.pem", "--capture", "est.jsonl"}, password...)...)
		}},
		{"enroll", func(t *testing.T) {
			c.Expect(t, 0, append([]string{"est", "enroll", "--server", open, "--tls-ca-cert", "ca.pem", "--subject", subject(t),
				"--cert-out", "enroll.pem", "--key-out", "enroll.key", "--capture", "est.jsonl"}, password...)...)
			c.CheckIssued(t, "enroll.pem", "ca.pem", "enroll.key")
		}},
		// The server runs with -o, so the TLS client certificate is enough.
		{"reenroll-certificate", func(t *testing.T) {
			c.Expect(t, 0, "est", "reenroll", "--server", open, "--tls-ca-cert", "ca.pem", "--cert", "enroll.pem", "--key", "enroll.key",
				"--cert-out", "reenroll-certificate.pem", "--key-out", "reenroll-certificate.key", "--capture", "est.jsonl")
			c.CheckIssued(t, "reenroll-certificate.pem", "ca.pem", "reenroll-certificate.key")
		}},
		{"reenroll-password", func(t *testing.T) {
			c.Expect(t, 0, append([]string{"est", "reenroll", "--server", open, "--tls-ca-cert", "ca.pem", "--cert", "enroll.pem",
				"--cert-out", "reenroll-password.pem", "--key-out", "reenroll-password.key", "--capture", "est.jsonl"}, password...)...)
			c.CheckIssued(t, "reenroll-password.pem", "ca.pem", "reenroll-password.key")
		}},
		// TLS-SRP authenticates the server, so no --tls-ca-cert is needed.
		{"srp", func(t *testing.T) {
			c.Expect(t, 0, "est", "enroll", "--server", open, "--srp", "--user", srpUser, "--password-file", "srppwd",
				"--subject", subject(t), "--cert-out", "srp.pem", "--key-out", "srp.key", "--capture", "est.jsonl")
			c.CheckIssued(t, "srp.pem", "ca.pem", "srp.key")
		}},
		{"tls-unique", func(t *testing.T) {
			c.Expect(t, 0, append([]string{"est", "enroll", "--server", bound, "--tls-ca-cert", "ca.pem", "--tls-unique",
				"--subject", subject(t), "--cert-out", "tls-unique.pem", "--key-out", "tls-unique.key", "--capture", "est.jsonl"}, password...)...)
			c.CheckIssued(t, "tls-unique.pem", "ca.pem", "tls-unique.key")
		}},
		{"tls-unique-missing", func(t *testing.T) {
			c.ExpectOutput(t, 3, "Proof of Possession Mismatch", append([]string{"est", "enroll", "--server", bound, "--tls-ca-cert", "ca.pem",
				"--subject", subject(t), "--cert-out", "tls-unique-missing.pem", "--key-out", "tls-unique-missing.key",
				"--capture", "est.jsonl"}, password...)...)
		}},
		// The server declares a Content-Length shorter than its multipart response.
		{"serverkeygen", func(t *testing.T) {
			c.ExpectOutput(t, 4, "unexpected EOF", append([]string{"est", "serverkeygen", "--server", open, "--tls-ca-cert", "ca.pem",
				"--subject", subject(t), "--cert-out", "serverkeygen.pem", "--key-out", "serverkeygen.key", "--capture", "est.jsonl"}, password...)...)
		}},
		{"inspect", func(t *testing.T) {
			c.Expect(t, 0, "inspect", "est.jsonl")
		}},
		// The only deviation is in the truncated serverkeygen response.
		{"lint", func(t *testing.T) {
			c.ExpectOutput(t, 6, "1 deviation in", "lint", "est.jsonl")
		}},
	}
	for _, step := range steps {
		// Each step uses the files that the steps before it wrote.
		if !t.Run(step.name, step.run) {
			t.FailNow()
		}
	}
}

// image returns the name of the example server image, LIBEST_IMAGE or certrally-libest.
func image() string {
	if name := os.Getenv("LIBEST_IMAGE"); name != "" {
		return name
	}
	return "certrally-libest"
}

// startServer starts the example server with the environment variables env and the extra estserver
// flags, waits until it answers over TLS and returns its URL. The container is removed when the test
// ends, and its log is shown when the test failed.
func startServer(t *testing.T, ca *x509.Certificate, env []string, flags ...string) string {
	t.Helper()
	args := make([]string, 0, 5+2*len(env)+len(flags))
	args = append(args, "run", "-d", "-p", "127.0.0.1::8085")
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image())
	id := strings.TrimSpace(string(docker(t, append(args, flags...)...)))
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("estserver %s log:\n%s", strings.Join(flags, " "), out)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	addr := strings.TrimSpace(string(docker(t, "port", id, "8085/tcp")))

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}
	url := "https://" + addr
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		resp, err := client.Get(url + "/.well-known/est/cacerts")
		if err == nil {
			_ = resp.Body.Close()
			return url
		}
	}
	t.Fatalf("estserver %s did not answer at %s within 15 seconds", strings.Join(flags, " "), url)
	return ""
}

// requireSame fails the test unless the PEM file holds exactly the certificate want.
func requireSame(t *testing.T, c *itest.Certrally, name string, want *x509.Certificate) {
	t.Helper()
	certs := c.Certificates(t, name)
	if len(certs) != 1 || !bytes.Equal(certs[0].Raw, want.Raw) {
		t.Fatalf("%s does not hold exactly the CA certificate of the server", name)
	}
}

// docker runs a docker command and returns its standard output.
func docker(t *testing.T, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), dockerTimeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}
