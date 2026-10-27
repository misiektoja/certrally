package cli

import (
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"

	"github.com/misiektoja/go-pki-cmp/examples/mockserver"
	"github.com/misiektoja/go-pki-cmp/server"
)

// testProxy is an HTTP proxy that tunnels CONNECT requests and forwards plain requests.
type testProxy struct {
	url string
	mu  sync.Mutex
	// connects are the CONNECT targets and forwards the URLs of the forwarded requests.
	connects []string
	forwards []string
}

// startProxy starts a proxy for one test.
func startProxy(t *testing.T) *testProxy {
	t.Helper()
	p := &testProxy{}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

// seen returns the CONNECT targets and forwarded URLs so far.
func (p *testProxy) seen() (connects, forwards []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...), append([]string(nil), p.forwards...)
}

// ServeHTTP tunnels a CONNECT request to its target and forwards any other request to its URL.
func (p *testProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		p.mu.Lock()
		p.forwards = append(p.forwards, r.URL.String())
		p.mu.Unlock()
		req := r.Clone(r.Context())
		req.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	p.mu.Lock()
	p.connects = append(p.connects, r.Host)
	p.mu.Unlock()
	upstream, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	client, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, client)
		_ = upstream.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.(*net.TCPConn).CloseWrite()
	<-done
}

// hostOf returns the host and port of a server URL.
func hostOf(t *testing.T, serverURL string) string {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestProxyCMP checks that --proxy forwards plain CMP requests through the proxy, tunnels HTTPS
// through it with CONNECT and applies to poll.
func TestProxyCMP(t *testing.T) {
	useSecret(t, testSecret)
	proxy := startProxy(t)
	plain := startCA(t, nil)
	code, _, errOut := run(t, "ping", "--server", plain.url, "--proxy", proxy.url)
	if code != exitOK {
		t.Fatalf("ping exited with %d:\n%s", code, errOut)
	}
	if _, forwards := proxy.seen(); len(forwards) != 1 || forwards[0] != plain.url {
		t.Errorf("forwarded %v, want %s", forwards, plain.url)
	}

	t.Run("enroll over HTTPS", func(t *testing.T) {
		ca := startTLSCA(t, nil)
		dir := t.TempDir()
		code, _, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--insecure", "--proxy", proxy.url,
			"--cert-out", filepath.Join(dir, "cert.pem"), "--key-out", filepath.Join(dir, "key.pem"))
		if code != exitOK {
			t.Fatalf("enroll exited with %d:\n%s", code, errOut)
		}
		if connects, _ := proxy.seen(); len(connects) == 0 || connects[len(connects)-1] != hostOf(t, ca.url) {
			t.Errorf("CONNECT targets %v, want %s", connects, hostOf(t, ca.url))
		}
	})
	t.Run("poll", func(t *testing.T) {
		ca := startTLSCA(t, func(m *mockserver.MockCA) server.CA {
			return &faultCA{MockCA: m, waiting: 1, pending: map[string]*pendingDecision{}}
		})
		dir := t.TempDir()
		certOut, captureFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "run.jsonl")
		code, out, errOut := run(t, "enroll", "--server", ca.url, "--ref", testRef, "--insecure", "--proxy", proxy.url,
			"--cert-out", certOut, "--key-out", filepath.Join(dir, "key.pem"), "--poll-later", "--capture", captureFile)
		if code != exitOK {
			t.Fatalf("enroll --poll-later exited with %d:\n%s", code, errOut)
		}
		connectsBefore, _ := proxy.seen()
		code, _, errOut = run(t, "poll", "--transaction-id", transactionIDIn(t, out), "--capture", captureFile,
			"--insecure", "--proxy", proxy.url)
		if code != exitOK {
			t.Fatalf("poll exited with %d:\n%s", code, errOut)
		}
		if connects, _ := proxy.seen(); len(connects) <= len(connectsBefore) {
			t.Error("poll did not connect through the proxy")
		}
		if readCert(t, certOut).Subject.CommonName != testRef {
			t.Error("the polled certificate has another subject")
		}
	})
}

// TestProxyEST checks that the EST commands tunnel through --proxy with CONNECT.
func TestProxyEST(t *testing.T) {
	usePassword(t, estTestPassword)
	proxy := startProxy(t)
	srv := startESTServer(t, nil, nil, nil)
	code, _, errOut := run(t, srv.args("cacerts", "--proxy", proxy.url)...)
	if code != exitOK {
		t.Fatalf("est cacerts exited with %d:\n%s", code, errOut)
	}
	if connects, _ := proxy.seen(); len(connects) != 1 || connects[0] != hostOf(t, srv.url) {
		t.Errorf("CONNECT targets %v, want %s", connects, hostOf(t, srv.url))
	}
}

// TestProxyUsage checks the error for a --proxy that is not an http or https URL.
func TestProxyUsage(t *testing.T) {
	useSecret(t, testSecret)
	usePassword(t, estTestPassword)
	for _, args := range [][]string{
		{"ping", "--server", "http://127.0.0.1:1", "--proxy", "socks5://127.0.0.1:1080"},
		{"est", "csrattrs", "--server", "https://127.0.0.1:1", "--proxy", "proxy.example.com:3128"},
	} {
		code, _, errOut := run(t, args...)
		if code != exitLocal || !errorContains(errOut, "is not an http or https URL") {
			t.Errorf("%q: exited with %d, want 1 and a usage error in:\n%s", args, code, errOut)
		}
	}
}
