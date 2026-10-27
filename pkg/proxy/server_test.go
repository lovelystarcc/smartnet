package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"smartnet/pkg/config"
	"smartnet/pkg/fakeip"
	"strings"

	xproxy "golang.org/x/net/proxy"
)

func getFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestProxyServerHTTPAndSOCKS5(t *testing.T) {
	// 1. Target HTTP test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from target"))
	}))
	defer ts.Close()

	// 2. Start proxy server on random free port
	port := getFreePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := config.DefaultConfig()
	cfg.ProxyAddr = proxyAddr

	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer srv.Stop()

	// Give it a brief moment to start listening
	time.Sleep(50 * time.Millisecond)

	if !IsListening(proxyAddr) {
		t.Fatalf("expected proxy to be listening on %s", proxyAddr)
	}

	// 3. Test HTTP proxy client
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 2 * time.Second,
	}

	resp, err := httpClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("HTTP GET via proxy failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "hello from target" {
		t.Errorf("expected body 'hello from target', got %q", string(body))
	}

	// 4. Test SOCKS5 client
	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, nil, xproxy.Direct)
	if err != nil {
		t.Fatalf("failed to create SOCKS5 dialer: %v", err)
	}

	socksHTTPClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
		Timeout: 2 * time.Second,
	}

	socksResp, err := socksHTTPClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("HTTP GET via SOCKS5 proxy failed: %v", err)
	}
	socksBody, _ := io.ReadAll(socksResp.Body)
	socksResp.Body.Close()

	if string(socksBody) != "hello from target" {
		t.Errorf("expected socks5 body 'hello from target', got %q", string(socksBody))
	}
}

func TestProxyFakeIPTranslation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fakeip-ok"))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	targetHost, targetPort, _ := net.SplitHostPort(u.Host)

	fakeIP := fakeip.DefaultPool.Allocate(targetHost)

	port := getFreePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := config.DefaultConfig()
	cfg.ProxyAddr = proxyAddr

	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := srv.dial(net.JoinHostPort(fakeIP.String(), targetPort))
	if err != nil {
		t.Fatalf("dial via Fake-IP failed: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !strings.Contains(string(respBytes), "fakeip-ok") {
		t.Errorf("expected response to contain 'fakeip-ok', got %s", string(respBytes))
	}
}

func TestProxyControlEndpoints(t *testing.T) {
	port := getFreePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := config.DefaultConfig()
	cfg.ProxyAddr = proxyAddr

	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start proxy server: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	// Allocate a Fake-IP
	fakeip.DefaultPool.Allocate("control-test.example.com")

	alloc, total, err := fakeip.QueryDaemonStats(proxyAddr)
	if err != nil {
		t.Fatalf("QueryDaemonStats failed: %v", err)
	}
	if alloc == 0 || total == 0 {
		t.Fatalf("expected non-zero allocation stats, got %d / %d", alloc, total)
	}

	// Clear daemon pool via IPC endpoint
	if err := fakeip.ClearDaemon(proxyAddr); err != nil {
		t.Fatalf("ClearDaemon failed: %v", err)
	}

	allocAfter, _, err := fakeip.QueryDaemonStats(proxyAddr)
	if err != nil {
		t.Fatalf("QueryDaemonStats after clear failed: %v", err)
	}
	if allocAfter != 0 {
		t.Fatalf("expected 0 allocations after clear, got %d", allocAfter)
	}
}
