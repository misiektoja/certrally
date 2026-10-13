package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPing checks that a CMP answer counts as a reply, with and without a pinned CA.
func TestPing(t *testing.T) {
	isolateColorEnv(t)
	ca := startCA(t, nil)
	other := startCA(t, nil)
	caCert := readCert(t, ca.caFile)

	tests := []struct {
		name     string
		extra    []string
		wantCode int
		want     []string
	}{
		{"auto", nil, exitOK, []string{"The server answers CMP", "error rejection badMessageCheck", caCert.Subject.String(), "ms"}},
		{"pinned", []string{"--ca-cert", ca.caFile}, exitOK, []string{"signed by the CA in --ca-cert"}},
		{"other CA", []string{"--ca-cert", other.caFile}, exitProtocol, []string{"not as the CA in --ca-cert"}},
		{"repeated", []string{"-c", "3", "-i", "0s"}, exitOK, []string{"  3  error", "3 of 3", "min "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"ping", "--server", ca.url}, tt.extra...)
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

	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
	}{
		{"not found", []string{"--server", notFound.URL}, exitTransport, "HTTP 404"},
		{"connection refused", []string{"--server", closed.URL, "-c", "2", "-i", "0s"}, exitTransport, "Check the host and port"},
		{"bad count", []string{"--server", notFound.URL, "-c", "0"}, exitLocal, "--count"},
		{"bad server", []string{"--server", "ftp://example.com"}, exitLocal, "--server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := run(t, append([]string{"ping"}, tt.args...)...)
			t.Log(errOut)
			if code != tt.wantCode || !strings.Contains(errOut, tt.want) {
				t.Errorf("exited with %d, want %d and %q in:\n%s", code, tt.wantCode, tt.want, errOut)
			}
		})
	}
}
