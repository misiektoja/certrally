package cli

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"

	"github.com/misiektoja/certrally/internal/secret"
)

// syncBuffer is a bytes.Buffer that a running command and a test can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p.
func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// mockRun is a mock CA that runs while a test talks to it.
type mockRun struct {
	url    string
	stdout *syncBuffer
	stderr *syncBuffer
	cancel context.CancelFunc
	done   chan int
}

// mockServerURL finds the server URL in the startup report.
var mockServerURL = regexp.MustCompile(`Server\s+(http://\S+)`)

// startMock runs the mock command with args until the test ends or stop is called.
func startMock(t *testing.T, args ...string) *mockRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &mockRun{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, done: make(chan int, 1)}
	go func() { m.done <- Run(ctx, append([]string{"mock"}, args...), m.stdout, m.stderr) }()
	t.Cleanup(func() {
		cancel()
		<-m.done
	})
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(m.stdout.String(), "Press Ctrl-C to stop.") {
		select {
		case code := <-m.done:
			m.done <- code
			t.Fatalf("mock exited with %d before it was ready:\n%s%s", code, m.stdout, m.stderr)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("mock did not start:\n%s%s", m.stdout, m.stderr)
		}
	}
	match := mockServerURL.FindStringSubmatch(m.stdout.String())
	if match == nil {
		t.Fatalf("startup report lacks the server URL:\n%s", m.stdout)
	}
	m.url = match[1]
	return m
}

// stop ends the mock as Ctrl-C does and returns its exit status.
func (m *mockRun) stop(t *testing.T) int {
	t.Helper()
	m.cancel()
	select {
	case code := <-m.done:
		m.done <- code
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("mock did not stop")
		return -1
	}
}

// TestMock checks that the commands work against the mock CA and that it logs and stops cleanly.
func TestMock(t *testing.T) {
	useSecret(t, "")
	dir := t.TempDir()
	secretFile, caFile := filepath.Join(dir, "secret.txt"), filepath.Join(dir, "ca.pem")
	writeFile(t, secretFile, []byte(testSecret+"\n"))
	m := startMock(t, "--listen", "127.0.0.1:0", "--ref", testRef, "--secret-file", secretFile, "--ca-out", caFile)
	if !strings.HasSuffix(m.url, mockPath) {
		t.Errorf("server URL %q does not end in %s", m.url, mockPath)
	}
	for _, want := range []string{"CN=Test CA", "from " + secretFile, caFile, "--ca-cert " + caFile, "--secret-file " + secretFile} {
		if !strings.Contains(m.stdout.String(), want) {
			t.Errorf("startup report lacks %q:\n%s", want, m.stdout)
		}
	}

	certOut, keyOut := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	connection := []string{"--server", m.url, "--ref", testRef, "--secret-file", secretFile, "--ca-cert", caFile}
	steps := [][]string{
		append([]string{"enroll", "--subject", "CN=device-42", "--cert-out", certOut, "--key-out", keyOut}, connection...),
		append([]string{"cacerts"}, connection...),
		{"revoke", "--server", m.url, "--ca-cert", caFile, "--cert", certOut, "--key", keyOut, "--yes"},
	}
	for _, args := range steps {
		if code, _, errOut := run(t, args...); code != exitOK {
			t.Fatalf("%s exited with %d:\n%s", args[0], code, errOut)
		}
	}

	name := strings.ToLower(compositemldsa.Algorithms()[0].String())
	code, _, errOut := run(t, append([]string{"enroll", "--key-type", name,
		"--cert-out", filepath.Join(dir, "c.pem"), "--key-out", filepath.Join(dir, "k.pem")}, connection...)...)
	if code != exitOK {
		t.Errorf("composite enroll exited with %d:\n%s", code, errOut)
	}

	resp, err := http.Get(strings.TrimSuffix(m.url, mockPath) + "/elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /elsewhere answered %d, want 404", resp.StatusCode)
	}

	if code := m.stop(t); code != exitOK {
		t.Errorf("mock exited with %d after it was stopped:\n%s", code, m.stderr)
	}
	out := m.stdout.String()
	for _, want := range []string{
		"ir  PBMAC1  CN=" + testRef + "  ->  ip  accepted",
		"certConf  PBMAC1",
		"genm  PBMAC1",
		"rr  ",
		"GET /elsewhere  ->  HTTP 404",
		"Mock CA stopped",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("request log lacks %q:\n%s", want, out)
		}
	}
	if errOut := m.stderr.String(); errOut != "" {
		t.Errorf("mock wrote to stderr:\n%s", errOut)
	}
}

// TestMockGeneratedSecret checks that the mock CA makes up a secret and that the printed command uses it.
func TestMockGeneratedSecret(t *testing.T) {
	useSecret(t, "")
	t.Chdir(t.TempDir())
	m := startMock(t, "--listen", "127.0.0.1:0", "--ca-out", "ca.pem")
	match := regexp.MustCompile(`(?m)^  (` + regexp.QuoteMeta(secret.EnvVar) + `=(\S+)) certrally (enroll .*)$`).FindStringSubmatch(m.stdout.String())
	if match == nil {
		t.Fatalf("startup report lacks an enroll command with the generated secret:\n%s", m.stdout)
	}
	if !strings.Contains(m.stdout.String(), match[2]+" (generated)") {
		t.Errorf("startup report does not show the generated secret:\n%s", m.stdout)
	}
	useSecret(t, match[2])
	if code, _, errOut := run(t, strings.Fields(match[3])...); code != exitOK {
		t.Fatalf("the printed command exited with %d:\n%s", code, errOut)
	}
	for _, file := range []string{"device.pem", "device.key"} {
		if _, err := os.Stat(file); err != nil {
			t.Error(err)
		}
	}
}

// TestMockErrors checks that the mock CA refuses to start on a bad command line.
func TestMockErrors(t *testing.T) {
	useSecret(t, testSecret)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	dir := t.TempDir()
	existing, unused := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "unused.pem")
	writeFile(t, existing, []byte("keep"))

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"empty reference", []string{"--ref", ""}, "--ref must not be empty"},
		{"address in use", []string{"--listen", busy.Addr().String(), "--ca-out", unused}, "--listen"},
		{"bad address", []string{"--listen", "nowhere"}, "--listen"},
		{"existing CA file", []string{"--listen", "127.0.0.1:0", "--ca-out", existing}, existing},
		{"arguments", []string{"extra"}, "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, append([]string{"mock"}, tt.args...)...)
			if code != exitLocal || !strings.Contains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d with %q:\n%s", code, exitLocal, tt.want, errOut)
			}
		})
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "keep" {
		t.Errorf("the existing CA file was changed: %q, %v", data, err)
	}
	if _, err := os.Stat(unused); !os.IsNotExist(err) {
		t.Errorf("a mock CA that did not start wrote %s: %v", unused, err)
	}
}

// TestMockURL checks the server URL and the remote access report for listen addresses.
func TestMockURL(t *testing.T) {
	tests := []struct {
		addr       net.Addr
		wantURL    string
		wantRemote bool
	}{
		{&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, "http://127.0.0.1:8080" + mockPath, false},
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 8080}, "http://[::1]:8080" + mockPath, false},
		{&net.TCPAddr{IP: net.IPv4zero, Port: 8080}, "http://localhost:8080" + mockPath, true},
		{&net.TCPAddr{IP: net.IPv6unspecified, Port: 8080}, "http://localhost:8080" + mockPath, true},
		{&net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 8080}, "http://192.0.2.7:8080" + mockPath, true},
	}
	for _, tt := range tests {
		url, remote := mockURL(tt.addr)
		if url != tt.wantURL || remote != tt.wantRemote {
			t.Errorf("mockURL(%s) = %q, %v, want %q, %v", tt.addr, url, remote, tt.wantURL, tt.wantRemote)
		}
	}
}
