package resolver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
	"smartnet/pkg/config"
	"smartnet/pkg/fakeip"
)

func TestIsLocalOrCaptive(t *testing.T) {
	testCases := []struct {
		domain   string
		expected bool
	}{
		{"captive.apple.com.", true},
		{"sub.captive.apple.com.", true},
		{"connectivitycheck.gstatic.com.", true},
		{"myrouter.local.", true},
		{"home.lan.", true},
		{"service.internal.", true},
		{"localhost.", true},
		{"google.com.", false},
		{"chatgpt.com.", false},
		{"spotify.com.", false},
	}

	for _, tc := range testCases {
		got := isLocalOrCaptive(tc.domain)
		if got != tc.expected {
			t.Errorf("isLocalOrCaptive(%q) = %v; want %v", tc.domain, got, tc.expected)
		}
	}
}

func TestCircuitBreaker(t *testing.T) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	if s.state != StateHealthy {
		t.Fatalf("expected initial state to be StateHealthy, got %v", s.state)
	}

	// 1st failure
	s.recordFailure("https://example.com/dns-query")
	if s.state != StateHealthy {
		t.Errorf("expected state to remain StateHealthy after 1 failure, got %v", s.state)
	}

	// 2nd failure
	s.recordFailure("https://example.com/dns-query")
	if s.state != StateHealthy {
		t.Errorf("expected state to remain StateHealthy after 2 failures, got %v", s.state)
	}

	// 3rd failure: should trip to StateDegraded
	s.recordFailure("https://example.com/dns-query")
	if s.state != StateDegraded {
		t.Errorf("expected state to transition to StateDegraded after 3 failures, got %v", s.state)
	}

	// Recovery
	s.recordSuccess("https://example.com/dns-query")
	if s.state != StateHealthy {
		t.Errorf("expected state to recover to StateHealthy, got %v", s.state)
	}
	if s.consecutiveFails != 0 {
		t.Errorf("expected consecutiveFails to reset to 0, got %d", s.consecutiveFails)
	}
}

func TestQueryFallback(t *testing.T) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	resp, err := s.queryFallback(req)
	if err != nil {
		t.Fatalf("queryFallback failed: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("expected non-empty DNS answer from fallback, got %v", resp)
	}
}

func TestCacheLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{93, 184, 216, 34},
	})

	// Pre-fill cache with MaxCacheEntries items
	s.cacheMu.Lock()
	for i := 0; i < MaxCacheEntries; i++ {
		s.cache[string(rune(i))] = cacheItem{
			msg:     msg.Copy(),
			expires: time.Now().Add(10 * time.Minute),
		}
	}
	s.cacheMu.Unlock()

	// Cache one more item, which triggers eviction
	s.cacheResponse("new_item", msg, false)

	s.cacheMu.RLock()
	cacheLen := len(s.cache)
	s.cacheMu.RUnlock()

	if cacheLen > MaxCacheEntries {
		t.Errorf("cache size %d exceeded maximum %d", cacheLen, MaxCacheEntries)
	}
}

func TestResolveViaBootstrap(t *testing.T) {
	ip, err := resolveViaBootstrap(context.Background(), "google.com", []string{"1.1.1.1:53", "8.8.8.8:53"})
	if err != nil {
		t.Fatalf("resolveViaBootstrap failed: %v", err)
	}
	if ip == "" {
		t.Fatal("expected non-empty IP from bootstrap resolution")
	}
}

func TestBackupUpstreamFailover(t *testing.T) {
	// Start mock backup DoH server
	backupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reqMsg := new(dns.Msg)
		_ = reqMsg.Unpack(body)

		resp := new(dns.Msg)
		resp.SetReply(reqMsg)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: reqMsg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("93.184.216.34"),
			},
		}
		wire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer backupServer.Close()

	cfg := config.DefaultConfig()
	_ = cfg.AddProfile(&config.Profile{
		Name:           "with-backup",
		Upstream:       "http://127.0.0.1:59999/dns-query",
		BackupUpstream: backupServer.URL,
	})
	_ = cfg.SetActive("with-backup")

	s := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	w := &mockDNSWriter{}
	s.handleDNS(w, req)

	if w.msg == nil || len(w.msg.Answer) == 0 {
		t.Fatalf("expected non-empty response from backup DoH, got %v", w.msg)
	}
	aRecord, ok := w.msg.Answer[0].(*dns.A)
	if !ok || !aRecord.A.Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("expected answer 93.184.216.34, got %v", w.msg.Answer)
	}
}

type mockDNSWriter struct {
	msg *dns.Msg
}

func (m *mockDNSWriter) LocalAddr() net.Addr       { return nil }
func (m *mockDNSWriter) RemoteAddr() net.Addr      { return nil }
func (m *mockDNSWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	return nil
}
func (m *mockDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockDNSWriter) Close() error               { return nil }
func (m *mockDNSWriter) TsigStatus() error          { return nil }
func (m *mockDNSWriter) TsigTimersOnly(bool)        {}
func (m *mockDNSWriter) Hijack()                    {}

func TestFakeIPResolution(t *testing.T) {
	cfg := config.DefaultConfig()
	_ = cfg.AddProfile(&config.Profile{
		Name:     "fakeip-test",
		Upstream: "https://1.1.1.1/dns-query",
		FakeIP:   true,
	})
	_ = cfg.SetActive("fakeip-test")

	s := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("chatgpt.com.", dns.TypeA)

	w := &mockDNSWriter{}
	s.handleDNS(w, req)

	if w.msg == nil || len(w.msg.Answer) == 0 {
		t.Fatal("expected Fake-IP answer in response")
	}

	aRecord, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A record, got %T", w.msg.Answer[0])
	}

	if !fakeip.DefaultPool.IsFakeIP(aRecord.A) {
		t.Fatalf("expected Fake-IP from 198.18.0.0/15, got %s", aRecord.A)
	}

	dom, ok := fakeip.DefaultPool.LookupIP(aRecord.A)
	if !ok || dom != "chatgpt.com" {
		t.Fatalf("expected reverse lookup chatgpt.com, got %s (ok=%v)", dom, ok)
	}
}

func TestCacheTTLDecrementAndMinTTL(t *testing.T) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	// Create a response with two records: TTL 300 and TTL 60
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("93.184.216.35"),
		},
	}

	cacheKey := "example.com.:1:1"
	s.cacheResponse(cacheKey, msg, false)

	// Verify that item in cache was stored with min TTL = 60
	s.cacheMu.RLock()
	item, found := s.cache[cacheKey]
	s.cacheMu.RUnlock()

	if !found {
		t.Fatal("expected item in cache")
	}

	remaining := time.Until(item.expires)
	if remaining > 61*time.Second || remaining < 58*time.Second {
		t.Errorf("expected cache expiry based on min TTL (60s), got %v", remaining)
	}

	// Manually advance expiry to simulate time elapsed (2s remaining)
	s.cacheMu.Lock()
	item.expires = time.Now().Add(2 * time.Second)
	s.cache[cacheKey] = item
	s.cacheMu.Unlock()

	// Query via handleDNS (which hits cache)
	w := &mockDNSWriter{}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	s.handleDNS(w, req)

	if w.msg == nil || len(w.msg.Answer) == 0 {
		t.Fatal("expected response from cache")
	}

	for i, rr := range w.msg.Answer {
		ttl := rr.Header().Ttl
		if ttl > 2 {
			t.Errorf("record %d TTL should be decremented to <= 2, got %d", i, ttl)
		}
	}
}

func TestStopIdempotent(t *testing.T) {
	cfg := config.DefaultConfig()
	s := New(cfg)

	// Calling Stop multiple times must not panic
	s.Stop()
	s.Stop()
}

func TestQueryFallbackIgnoresServfail(t *testing.T) {
	// Listener 1: returns SERVFAIL immediately
	pc1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket 1 failed: %v", err)
	}
	defer pc1.Close()

	srv1 := &dns.Server{
		PacketConn: pc1,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv1.ActivateAndServe() }()
	defer func() { _ = srv1.Shutdown() }()

	// Listener 2: returns NOERROR with an A record after a slight delay
	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket 2 failed: %v", err)
	}
	defer pc2.Close()

	srv2 := &dns.Server{
		PacketConn: pc2,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			time.Sleep(30 * time.Millisecond)
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("1.2.3.4"),
				},
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv2.ActivateAndServe() }()
	defer func() { _ = srv2.Shutdown() }()

	cfg := config.DefaultConfig()
	s := New(cfg)
	s.fallbackServers = []string{pc1.LocalAddr().String(), pc2.LocalAddr().String()}

	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)

	resp, err := s.queryFallback(req)
	if err != nil {
		t.Fatalf("expected queryFallback to succeed despite first server SERVFAIL, got error: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess from second server, got rcode: %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected non-empty answers in response")
	}
}

func TestQueryDoHOverlongBodyRejected(t *testing.T) {
	// Start an HTTP server that returns > 65535 bytes
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				// Write HTTP OK response with 70,000 bytes
				body := make([]byte, 70000)
				respHdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n", len(body))
				_, _ = c.Write([]byte(respHdr))
				_, _ = c.Write(body)
			}(conn)
		}
	}()

	cfg := config.DefaultConfig()
	s := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("example.test.", dns.TypeA)

	dohURL := "http://" + ln.Addr().String() + "/dns-query"
	_, err = s.queryDoHWithTimeout(req, dohURL, 2*time.Second)
	if err == nil {
		t.Fatal("expected error for DoH response exceeding 65535 bytes, got nil")
	}
}


