package cli

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestPing checks that a CMP answer counts as a reply, with and without a pinned CA.
func TestPing(t *testing.T) {
	isolateColorEnv(t)
	ca := startCA(t, nil)
	other := startCA(t, nil)
	caCert := readCert(t, ca.caFile)

	unprotected := rejectingServer(t, badRequest)

	tests := []struct {
		name     string
		server   string
		extra    []string
		wantCode int
		want     []string
	}{
		{"auto", ca.url, nil, exitOK, []string{"The server answers CMP", "error rejection badMessageCheck", caCert.Subject.String(), "ms"}},
		{"pinned", ca.url, []string{"--ca-cert", ca.caFile}, exitOK, []string{"signed by the CA in --ca-cert"}},
		{"other CA", ca.url, []string{"--ca-cert", other.caFile}, exitProtocol, []string{"not as the CA in --ca-cert"}},
		{"unprotected", unprotected, []string{"--ca-cert", ca.caFile}, exitProtocol,
			[]string{"cannot be checked against --ca-cert", "does not protect its answer"}},
		{"repeated", ca.url, []string{"-c", "3", "-i", "0s"}, exitOK, []string{"  3  error", "3 of 3", "min "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"ping", "--server", tt.server}, tt.extra...)
			code, out, errOut := run(t, args...)
			t.Log(errOut + out)
			if code != tt.wantCode {
				t.Fatalf("exited with %d, want %d:\n%s%s", code, tt.wantCode, errOut, out)
			}
			for _, want := range tt.want {
				if !strings.Contains(out+errOut, want) {
					t.Errorf("output lacks %q:\n%s%s", want, errOut, out)
				}
			}
		})
	}
}

// TestPingNoAnswer checks that a server that does not answer with CMP fails with the transport status.
func TestPingNoAnswer(t *testing.T) {
	isolateColorEnv(t)
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	// The test certificate names 127.0.0.1 and example.com but not localhost. Trusting it lets the
	// host name check fail on every platform verifier.
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsServer.Close)
	tlsCA := filepath.Join(t.TempDir(), "tls-ca.pem")
	writeFile(t, tlsCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}))
	wrongHost := strings.Replace(tlsServer.URL, "127.0.0.1", "localhost", 1)

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{"not found", []string{"--server", notFound.URL}, exitTransport, "HTTP 404"},
		{"connection refused", []string{"--server", closed.URL, "-c", "2", "-i", "0s"}, exitTransport, "Check the host and port"},
		{"untrusted HTTPS", []string{"--server", tlsServer.URL}, exitTransport, "Pass its CA with --tls-ca-cert"},
		{"wrong HTTPS host", []string{"--server", wrongHost, "--tls-ca-cert", tlsCA}, exitTransport, "issued for another host name"},
		{"bad count", []string{"--server", notFound.URL, "-c", "0"}, exitLocal, "--count"},
		{"bad server", []string{"--server", "ftp://example.com"}, exitLocal, "--server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, append([]string{"ping"}, tt.args...)...)
			t.Log(errOut)
			if code != tt.wantCode || !errorContains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.wantCode, tt.want, errOut)
			}
		})
	}
}
