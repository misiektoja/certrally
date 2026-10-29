//go:build integration

// Package micromdm runs the SCEP commands of certrally against the SCEP server of micromdm/scep,
// built from the Dockerfile in this directory.
package micromdm

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	// challenge is the challenge password the server runs with.
	challenge = "certrally-micromdm"
	// dockerTimeout limits one docker command.
	dockerTimeout = time.Minute
)

// TestMicromdm runs each SCEP operation that micromdm/scep supports. The server encrypts every
// CertRep with single DES whatever the request used, so a request that gets a certificate needs
// --allow-des.
func TestMicromdm(t *testing.T) {
	c := itest.New(t)
	ca := docker(t, "run", "--rm", "--entrypoint", "cat", image(), "/depot/ca.pem")
	c.WriteFile(t, "ca.pem", ca)
	c.WriteFile(t, "challenge", []byte(challenge+"\n"))
	c.WriteFile(t, "wrong", []byte("wrong\n"))
	caCert := c.Certificates(t, "ca.pem")[0]
	fingerprint := sha256.Sum256(caCert.Raw)
	server := startServer(t)
	// enroll returns the arguments of scep enroll for a certificate named after the step.
	enroll := func(t *testing.T, challengeFile string, extra ...string) []string {
		name := strings.ReplaceAll(t.Name(), "/", "-")
		return append([]string{"scep", "enroll", "--server", server, "--ca-cert", "ca.pem", "--challenge-file", challengeFile,
			"--subject", "CN=certrally-" + name, "--cert-out", name + ".pem", "--key-out", name + ".key", "--capture", "scep.jsonl"}, extra...)
	}

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"caps", func(t *testing.T) {
			c.ExpectOutput(t, 0, "POSTPKIOperation", "scep", "caps", "--server", server, "--capture", "scep.jsonl")
		}},
		{"cacert", func(t *testing.T) {
			c.Expect(t, 0, "scep", "cacert", "--server", server, "--fingerprint", hex.EncodeToString(fingerprint[:]),
				"--out", "cacert.pem", "--capture", "scep.jsonl")
			certs := c.Certificates(t, "cacert.pem")
			if len(certs) != 1 || !bytes.Equal(certs[0].Raw, caCert.Raw) {
				t.Fatal("cacert.pem does not hold exactly the CA certificate of the server")
			}
		}},
		{"des-refused", func(t *testing.T) {
			c.ExpectOutput(t, 4, "--allow-des", enroll(t, "challenge")...)
		}},
		{"enroll-rsa", func(t *testing.T) {
			c.Expect(t, 0, enroll(t, "challenge", "--allow-des")...)
			c.CheckIssued(t, "TestMicromdm-enroll-rsa.pem", "ca.pem", "TestMicromdm-enroll-rsa.key")
		}},
		{"enroll-ecdsa", func(t *testing.T) {
			c.Expect(t, 0, enroll(t, "challenge", "--allow-des", "--key-type", "ecdsa-p256")...)
			c.CheckIssued(t, "TestMicromdm-enroll-ecdsa.pem", "ca.pem", "TestMicromdm-enroll-ecdsa.key")
		}},
		{"enroll-legacy", func(t *testing.T) {
			c.Expect(t, 0, enroll(t, "challenge", "--allow-des", "--hash", "sha1", "--cipher", "des3")...)
			c.CheckIssued(t, "TestMicromdm-enroll-legacy.pem", "ca.pem", "TestMicromdm-enroll-legacy.key")
		}},
		// micromdm/scep checks the challenge password in a RenewalReq too.
		{"renew", func(t *testing.T) {
			c.Expect(t, 0, "scep", "renew", "--server", server, "--ca-cert", "ca.pem", "--challenge-file", "challenge",
				"--cert", "TestMicromdm-enroll-rsa.pem", "--key", "TestMicromdm-enroll-rsa.key", "--allow-des",
				"--cert-out", "renew.pem", "--key-out", "renew.key", "--capture", "scep.jsonl")
			c.CheckIssued(t, "renew.pem", "ca.pem", "renew.key")
		}},
		{"wrong-challenge", func(t *testing.T) {
			c.ExpectOutput(t, 3, "badRequest", enroll(t, "wrong", "--allow-des")...)
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

// image returns the name of the server image, MICROMDM_IMAGE or certrally-micromdm-scep.
func image() string {
	if name := os.Getenv("MICROMDM_IMAGE"); name != "" {
		return name
	}
	return "certrally-micromdm-scep"
}

// startServer starts the server with the challenge password, waits until it answers GetCACaps and
// returns its SCEP URL. The container is removed when the test ends, and its log is shown when the
// test failed.
func startServer(t *testing.T) string {
	t.Helper()
	id := strings.TrimSpace(string(docker(t, "run", "-d", "-p", "127.0.0.1::8080", image(), "-challenge", challenge)))
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("scepserver log:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	addr := strings.TrimSpace(string(docker(t, "port", id, "8080/tcp")))
	url := "http://" + addr + "/scep"
	client := &http.Client{Timeout: time.Second}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		resp, err := client.Get(url + "?operation=GetCACaps")
		if err == nil {
			_ = resp.Body.Close()
			return url
		}
	}
	t.Fatalf("scepserver did not answer at %s within 15 seconds", url)
	return ""
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
