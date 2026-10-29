//go:build integration

// Package scepmock runs the SCEP commands of certrally against certrally scep mock, which serves
// the scepserver package of go-scep.
package scepmock

import (
	"bytes"
	"crypto/x509"
	"os"
	"regexp"
	"testing"

	"github.com/misiektoja/certrally/test/integration/internal/itest"
)

// mockReady is the last line of the startup report of scep mock.
const mockReady = "Press Ctrl-C to stop."

// mockReport finds the server URL and the CA fingerprint in the startup report.
var mockReport = regexp.MustCompile(`Server\s+(http://\S+)[\s\S]*SHA-256\s+([0-9a-f]{64})`)

// TestSCEPMock runs each SCEP operation against a mock CA with a challenge password and an RA
// certificate, and the pending path against a mock CA that answers PENDING once.
func TestSCEPMock(t *testing.T) {
	c := itest.New(t)
	c.WriteFile(t, "challenge", []byte("certrally-mock\n"))
	c.WriteFile(t, "wrong", []byte("wrong\n"))
	server, fingerprint := startMock(t, c, "--challenge-file", "challenge", "--ra", "--next-ca", "--ca-out", "ca.pem")
	pending, _ := startMock(t, c, "--any-challenge", "--pending-polls", "1", "--ca-out", "pending-ca.pem")
	// enroll returns the arguments of scep enroll for a certificate named after the step.
	enroll := func(t *testing.T, challengeFile string, extra ...string) []string {
		name := t.Name()[len("TestSCEPMock/"):]
		return append([]string{"scep", "enroll", "--server", server, "--ca-cert", "ca.pem", "--challenge-file", challengeFile,
			"--subject", "CN=certrally-" + name, "--cert-out", name + ".pem", "--key-out", name + ".key", "--capture", "scep.jsonl"}, extra...)
	}
	var issued *x509.Certificate

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"caps", func(t *testing.T) {
			c.ExpectOutput(t, 0, "Renewal", "scep", "caps", "--server", server, "--capture", "scep.jsonl")
		}},
		{"cacert", func(t *testing.T) {
			c.ExpectOutput(t, 0, "RA", "scep", "cacert", "--server", server, "--fingerprint", fingerprint, "--out", "cacert.pem",
				"--capture", "scep.jsonl")
			requireSame(t, c, "cacert.pem", "ca.pem")
		}},
		// The fingerprint vouches only for the issuing CA, so the root of the chain is not saved.
		{"chain", func(t *testing.T) {
			c.ExpectOutput(t, 0, "chain of 2 certificates", "scep", "chain", "--server", server, "--fingerprint", fingerprint,
				"--out", "chain.pem", "--capture", "scep.jsonl")
			if chain := c.Certificates(t, "chain.pem"); len(chain) != 1 || !bytes.Equal(chain[0].Raw, c.Certificates(t, "ca.pem")[0].Raw) {
				t.Fatal("chain.pem does not hold exactly the issuing CA certificate")
			}
		}},
		{"nextca", func(t *testing.T) {
			c.Expect(t, 0, "scep", "nextca", "--server", server, "--ca-cert", "ca.pem", "--out", "nextca.pem", "--capture", "scep.jsonl")
			c.Certificates(t, "nextca.pem")
		}},
		{"enroll-rsa", func(t *testing.T) {
			c.Expect(t, 0, enroll(t, "challenge")...)
			issued = c.CheckIssued(t, "enroll-rsa.pem", "ca.pem", "enroll-rsa.key")
		}},
		{"enroll-ecdsa", func(t *testing.T) {
			c.Expect(t, 0, enroll(t, "challenge", "--key-type", "ecdsa-p384")...)
			c.CheckIssued(t, "enroll-ecdsa.pem", "ca.pem", "enroll-ecdsa.key")
		}},
		{"enroll-legacy", func(t *testing.T) {
			c.Expect(t, 0, enroll(t, "challenge", "--hash", "sha1", "--cipher", "des3")...)
			c.CheckIssued(t, "enroll-legacy.pem", "ca.pem", "enroll-legacy.key")
		}},
		{"renew", func(t *testing.T) {
			c.Expect(t, 0, "scep", "renew", "--server", server, "--ca-cert", "ca.pem", "--cert", "enroll-rsa.pem", "--key", "enroll-rsa.key",
				"--cert-out", "renew.pem", "--key-out", "renew.key", "--capture", "scep.jsonl")
			c.CheckIssued(t, "renew.pem", "ca.pem", "renew.key")
		}},
		{"getcert", func(t *testing.T) {
			c.Expect(t, 0, "scep", "getcert", "--server", server, "--ca-cert", "ca.pem", "--cert", "enroll-rsa.pem", "--key", "enroll-rsa.key",
				"--serial", issued.SerialNumber.String(), "--out", "getcert.pem", "--capture", "scep.jsonl")
			if got := c.Certificates(t, "getcert.pem"); !bytes.Equal(got[0].Raw, issued.Raw) {
				t.Fatal("getcert.pem does not hold the certificate with the serial number")
			}
		}},
		{"getcrl", func(t *testing.T) {
			c.Expect(t, 0, "scep", "getcrl", "--server", server, "--ca-cert", "ca.pem", "--cert", "enroll-rsa.pem", "--key", "enroll-rsa.key",
				"--out", "ca.crl", "--capture", "scep.jsonl")
		}},
		{"wrong-challenge", func(t *testing.T) {
			c.ExpectOutput(t, 3, "badRequest", enroll(t, "wrong")...)
		}},
		{"pending", func(t *testing.T) {
			c.ExpectOutput(t, 0, "PENDING", "scep", "enroll", "--server", pending, "--ca-cert", "pending-ca.pem", "--challenge", "any",
				"--subject", "CN=certrally-pending", "--poll-later", "--cert-out", "pending.pem", "--key-out", "pending.key",
				"--capture", "scep.jsonl")
		}},
		{"poll", func(t *testing.T) {
			c.Expect(t, 0, "scep", "poll", "--state", "pending.pem.state", "--capture", "scep.jsonl")
			c.CheckIssued(t, "pending.pem", "pending-ca.pem", "pending.key")
			if _, err := os.Stat(c.Path("pending.pem.state")); !os.IsNotExist(err) {
				t.Fatalf("the state file is still there after the certificate was issued: %v", err)
			}
		}},
		{"inspect", func(t *testing.T) {
			c.Expect(t, 0, "inspect", "scep.jsonl")
		}},
		{"lint", func(t *testing.T) {
			c.Expect(t, 0, "lint", "scep.jsonl")
		}},
	}
	for _, step := range steps {
		// Each step uses the files that the steps before it wrote.
		if !t.Run(step.name, step.run) {
			t.FailNow()
		}
	}
}

// startMock starts scep mock on a free port with the extra flags and returns its SCEP URL and the
// SHA-256 fingerprint of its CA certificate.
func startMock(t *testing.T, c *itest.Certrally, flags ...string) (string, string) {
	t.Helper()
	report := c.Start(t, mockReady, append([]string{"scep", "mock", "--listen", "127.0.0.1:0"}, flags...)...)
	match := mockReport.FindStringSubmatch(report)
	if match == nil {
		t.Fatalf("the startup report of scep mock lacks the server URL or the fingerprint:\n%s", report)
	}
	return match[1], match[2]
}

// requireSame fails the test unless the PEM files hold the same certificates.
func requireSame(t *testing.T, c *itest.Certrally, name, want string) {
	t.Helper()
	got, expected := c.Certificates(t, name), c.Certificates(t, want)
	if len(got) != len(expected) {
		t.Fatalf("%s holds %d certificates, %s holds %d", name, len(got), want, len(expected))
	}
	for i := range got {
		if !bytes.Equal(got[i].Raw, expected[i].Raw) {
			t.Fatalf("certificate %d of %s differs from %s", i+1, name, want)
		}
	}
}
