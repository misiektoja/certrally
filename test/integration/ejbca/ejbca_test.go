//go:build integration

// Package ejbca runs certrally against EJBCA Community Edition. make setup-ejbca starts the server
// from docker-compose.yml and creates its CA and CMP alias.
package ejbca

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/misiektoja/certrally/test/integration/internal/itest"
)

// cliTimeout limits one call of the EJBCA command line, which starts a JVM in the container.
const cliTimeout = time.Minute

// TestEJBCA sends every CMP request type to the certrally CMP alias and checks the behaviour that
// docs/interop.md describes. Every run registers its own end entities, so it can run again on the
// same EJBCA.
func TestEJBCA(t *testing.T) {
	base := "http://127.0.0.1:" + httpPort()
	requireEJBCA(t, base)
	url := base + "/ejbca/publicweb/cmp/certrally"
	c := itest.New(t)
	testCA := caCertificate(t, "TestCA")
	managementCA := caCertificate(t, "ManagementCA")
	c.WriteFile(t, "testca.pem", testCA)
	// EJBCA signs revocation responses with its ManagementCA.
	c.WriteFile(t, "both.pem", append(testCA, managementCA...))
	secret := randomHex(t, 16)
	c.WriteFile(t, "secret.txt", []byte(secret+"\n"))

	run := "certrally-" + randomHex(t, 4)
	user := func(name string) string { return run + "-" + name }
	keyTypes := []string{"ecdsa-p256", "rsa-2048", "ed25519", "ml-dsa-65"}
	names := make([]string, 0, len(keyTypes)+3)
	names = append(names, user("pbm"), user("strict"), user("p10cr"))
	for _, kt := range keyTypes {
		names = append(names, user(kt))
	}
	registerEndEntities(t, secret, names...)

	// A request with a shared secret names the end entity with --ref and asks for its subject.
	enroll := func(name string, args ...string) []string {
		return append([]string{"enroll", "--server", url, "--ref", user(name), "--secret-file", "secret.txt",
			"--subject", "CN=" + user(name), "--ca-cert", "testca.pem", "--capture", "cmp.jsonl"}, args...)
	}
	// EJBCA signs its responses to MAC-protected requests.
	const signedWarning = "response is signed, but the request is MAC-protected"

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"ir", func(t *testing.T) {
			for _, kt := range keyTypes {
				t.Run(kt, func(t *testing.T) {
					c.ExpectOutput(t, 0, signedWarning, enroll(kt, "--key-type", kt, "--cert-out", kt+".pem", "--key-out", kt+".key")...)
					c.CheckIssued(t, kt+".pem", "testca.pem", kt+".key")
				})
			}
		}},
		{"ir-pbm", func(t *testing.T) {
			c.Expect(t, 0, enroll("pbm", "--mac", "pbm", "--cert-out", "pbm.pem", "--key-out", "pbm.key")...)
			c.CheckIssued(t, "pbm.pem", "testca.pem", "pbm.key")
		}},
		{"ir-strict", func(t *testing.T) {
			c.ExpectOutput(t, 6, signedWarning, enroll("strict", "--profile", "strict", "--cert-out", "strict.pem", "--key-out", "strict.key")...)
		}},
		// EJBCA accepts a cr only from an end entity in status NEW, FAILED or INPROCESS.
		{"cr-before-reset", func(t *testing.T) {
			c.ExpectOutput(t, 3, "Status NEW, FAILED or INPROCESS required", "enroll", "--server", url, "--type", "cr",
				"--cert", "ecdsa-p256.pem", "--key", "ecdsa-p256.key", "--subject", "CN="+user("ecdsa-p256"),
				"--ca-cert", "testca.pem", "--cert-out", "cr.pem", "--key-out", "cr.key", "--capture", "cmp.jsonl")
		}},
		{"cr", func(t *testing.T) {
			ejbcaCLI(t, "ra", "setendentitystatus", user("ecdsa-p256"), "10")
			c.Expect(t, 0, "enroll", "--server", url, "--type", "cr", "--cert", "ecdsa-p256.pem", "--key", "ecdsa-p256.key",
				"--subject", "CN="+user("ecdsa-p256"), "--ca-cert", "testca.pem", "--cert-out", "cr.pem", "--key-out", "cr.key",
				"--capture", "cmp.jsonl")
			c.CheckIssued(t, "cr.pem", "testca.pem", "cr.key")
		}},
		{"kur", func(t *testing.T) {
			c.Expect(t, 0, "enroll", "--server", url, "--type", "kur", "--cert", "cr.pem", "--key", "cr.key",
				"--ca-cert", "testca.pem", "--cert-out", "kur.pem", "--key-out", "kur.key", "--capture", "cmp.jsonl")
			if cert := c.CheckIssued(t, "kur.pem", "testca.pem", "kur.key"); cert.Subject.CommonName != user("ecdsa-p256") {
				t.Errorf("the kur certificate is for %s, want CN=%s", cert.Subject, user("ecdsa-p256"))
			}
		}},
		{"p10cr", func(t *testing.T) {
			c.Expect(t, 0, "keygen", "--out", "p10cr.key", "--csr-out", "p10cr.csr", "--subject", "CN="+user("p10cr"))
			c.ExpectOutput(t, 0, signedWarning, "enroll", "--server", url, "--type", "p10cr", "--ref", user("p10cr"),
				"--secret-file", "secret.txt", "--csr", "p10cr.csr", "--ca-cert", "testca.pem", "--cert-out", "p10cr.pem",
				"--capture", "cmp.jsonl")
			c.CheckIssued(t, "p10cr.pem", "testca.pem", "p10cr.key")
		}},
		// EJBCA revokes the certificate, but its response is signed by the ManagementCA.
		{"rr-testca-only", func(t *testing.T) {
			c.ExpectOutput(t, 4, "The response is not signed by the CA in --ca-cert", "revoke", "--server", url,
				"--cert", "p10cr.pem", "--key", "p10cr.key", "--ca-cert", "testca.pem", "--yes", "--capture", "cmp.jsonl")
		}},
		{"rr", func(t *testing.T) {
			c.Expect(t, 0, "revoke", "--server", url, "--cert", "pbm.pem", "--key", "pbm.key", "--ca-cert", "both.pem", "--yes",
				"--capture", "cmp.jsonl")
		}},
		{"inspect", func(t *testing.T) {
			c.Expect(t, 0, "inspect", "cmp.jsonl", "--ca-cert", "both.pem", "--secret-file", "secret.txt")
		}},
		{"lint", func(t *testing.T) {
			c.ExpectOutput(t, 6, signedWarning, "lint", "cmp.jsonl", "--ca-cert", "both.pem")
		}},
	}
	for _, step := range steps {
		// Each step uses the files that the steps before it wrote.
		if !t.Run(step.name, step.run) {
			t.FailNow()
		}
	}
}

// httpPort returns the host port of the EJBCA HTTP endpoint, EJBCA_HTTP_PORT or 8080.
func httpPort() string {
	if port := os.Getenv("EJBCA_HTTP_PORT"); port != "" {
		return port
	}
	return "8080"
}

// requireEJBCA fails the test unless the EJBCA health check at base answers.
func requireEJBCA(t *testing.T, base string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/ejbca/publicweb/healthcheck/ejbcahealth", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return
		}
		err = errors.New(resp.Status)
	}
	t.Fatalf("EJBCA at %s is not ready: %v. Run make setup-ejbca first", base, err)
}

// registerEndEntities registers end entities of TestCA with secret as their password and stores
// it in clear text, which EJBCA needs to check a MAC. The calls run in parallel because each one
// starts a JVM.
func registerEndEntities(t *testing.T, secret string, names ...string) {
	t.Helper()
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			if _, err := runCLI("ra", "addendentity", "--username", name, "--dn", "CN="+name, "--caname", "TestCA",
				"--type", "1", "--token", "USERGENERATED", "--certprofile", "ENDUSER", "--eeprofile", "EMPTY",
				"--password", secret); err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = runCLI("ra", "setclearpwd", name, secret)
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
}

// caCertificate returns the PEM certificate of the named EJBCA CA.
func caCertificate(t *testing.T, name string) []byte {
	t.Helper()
	path := "/tmp/certrally-" + name + ".pem"
	ejbcaCLI(t, "ca", "getcacert", "--caname", name, "-f", path)
	out, err := dockerExec("cat", path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(out)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("EJBCA returned no certificate for %s", name)
	}
	return pem.EncodeToMemory(block)
}

// ejbcaCLI runs the EJBCA command line and fails the test when the command fails.
func ejbcaCLI(t *testing.T, args ...string) {
	t.Helper()
	if _, err := runCLI(args...); err != nil {
		t.Fatal(err)
	}
}

// runCLI runs the EJBCA command line in the container and returns its output.
func runCLI(args ...string) ([]byte, error) {
	return dockerExec(append([]string{"/opt/keyfactor/bin/ejbca.sh"}, args...)...)
}

// dockerExec runs a command in the EJBCA container that docker-compose.yml describes.
func dockerExec(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", "docker-compose.yml", "exec", "-T", "ejbca"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %w\n%s", args, err, out)
	}
	return out, nil
}

// randomHex returns n random bytes in hexadecimal.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
