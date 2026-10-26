//go:build integration

// Package itest runs the certrally binary for the integration tests and checks the files it writes.
package itest

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misiektoja/certrally/internal/keys"
	"github.com/misiektoja/certrally/internal/pemfile"
)

// commandTimeout limits one certrally run. It is shorter than the default --timeout, so a server
// that stops answering fails the test before the go test deadline.
const commandTimeout = 2 * time.Minute

// maxClockSkew is how far a server clock may run ahead of the test clock.
const maxClockSkew = time.Minute

// Certrally runs the binary that CERTRALLY_BIN names in a temporary working directory.
type Certrally struct {
	bin string
	// Dir is the working directory of every run. Relative file names in arguments resolve in it.
	Dir string
}

// New returns a runner for the binary in CERTRALLY_BIN with a new temporary working directory.
func New(t *testing.T) *Certrally {
	t.Helper()
	bin := os.Getenv("CERTRALLY_BIN")
	if bin == "" {
		t.Fatal("CERTRALLY_BIN is not set. Run the integration tests through make, such as make test-integration-openssl")
	}
	return &Certrally{bin: bin, Dir: t.TempDir()}
}

// Path returns the path of name in the working directory.
func (c *Certrally) Path(name string) string {
	return filepath.Join(c.Dir, name)
}

// Run runs certrally with args and returns its combined output and exit status. Standard input is
// empty, so certrally never waits for an answer, and colour is off whatever the environment says.
func (c *Certrally) Run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), commandTimeout)
	defer cancel()
	argv := slices.Concat(args, []string{"--color", "never"})
	cmd := exec.CommandContext(ctx, c.bin, argv...) //nolint:gosec // G204: the tests choose the arguments.
	cmd.Dir = c.Dir
	out, err := cmd.CombinedOutput()
	t.Logf("$ certrally %s\n%s", strings.Join(args, " "), out)
	if ctx.Err() != nil {
		t.Fatalf("certrally did not finish within %s", commandTimeout)
	}
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run certrally: %v", err)
	}
	return string(out), exitErr.ExitCode()
}

// Expect runs certrally and fails the test unless it exits with status want. It returns the output.
func (c *Certrally) Expect(t *testing.T, want int, args ...string) string {
	t.Helper()
	out, status := c.Run(t, args...)
	if status != want {
		t.Fatalf("certrally exited with status %d, want %d", status, want)
	}
	return out
}

// ExpectOutput is Expect that also requires the output to contain text.
func (c *Certrally) ExpectOutput(t *testing.T, want int, text string, args ...string) {
	t.Helper()
	if out := c.Expect(t, want, args...); !strings.Contains(out, text) {
		t.Fatalf("the output does not contain %q", text)
	}
}

// CheckIssued fails the test unless the first certificate in certFile chains to a CA certificate
// in caFile and certifies the private key in keyFile. It returns that certificate.
func (c *Certrally) CheckIssued(t *testing.T, certFile, caFile, keyFile string) *x509.Certificate {
	t.Helper()
	certs := c.Certificates(t, certFile)
	roots := x509.NewCertPool()
	for _, ca := range c.Certificates(t, caFile) {
		roots.AddCert(ca)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   time.Now(),
	}
	// Some servers start a certificate at the moment they issue it, and a server in a container can
	// run slightly ahead of the host clock, as in the Docker Desktop VM.
	if skew := certs[0].NotBefore.Sub(opts.CurrentTime); skew > 0 && skew <= maxClockSkew {
		opts.CurrentTime = certs[0].NotBefore
	}
	if _, err := certs[0].Verify(opts); err != nil {
		t.Fatalf("%s does not chain to %s: %v", certFile, caFile, err)
	}
	c.CheckKey(t, certs[0], keyFile)
	return certs[0]
}

// CheckKey fails the test unless keyFile holds the private key that cert certifies and only its
// owner can read the file.
func (c *Certrally) CheckKey(t *testing.T, cert *x509.Certificate, keyFile string) {
	t.Helper()
	path := c.Path(keyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s has mode %o, want 600", keyFile, perm)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the file is in the test directory.
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Parse(data)
	if err != nil {
		t.Fatalf("%s: %v", keyFile, err)
	}
	certKey, err := keys.CertificateKey(cert)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := keys.Public(key).(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(certKey) {
		t.Fatalf("the certificate does not certify the key in %s", keyFile)
	}
}

// Certificates reads the certificates of a PEM file in the working directory. It fails the test
// when the file holds none.
func (c *Certrally) Certificates(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	certs, err := pemfile.ReadCertificates(c.Path(name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(certs) == 0 {
		t.Fatalf("%s holds no certificate", name)
	}
	return certs
}

// WriteFile writes data to name in the working directory with mode 0600.
func (c *Certrally) WriteFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(c.Path(name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
