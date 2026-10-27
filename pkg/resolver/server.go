package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"smartnet/pkg/config"
	"smartnet/pkg/fakeip"
	"smartnet/pkg/network"
	"smartnet/pkg/rules"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type UpstreamState int

const (
	StateHealthy UpstreamState = iota
	StateDegraded
)

const MaxCacheEntries = 10000

func (s UpstreamState) String() string {
	switch s {
	case StateHealthy:
		return "Healthy"
	case StateDegraded:
		return "Degraded (Fallback Active)"
	default:
		return "Unknown"
	}
}

type cacheItem struct {
	msg     *dns.Msg
	expires time.Time
}

type Server struct {
	cfg       *config.Config
	cache     map[string]cacheItem
	cacheMu   sync.RWMutex
	client    *http.Client
	transport *http.Transport
	udpServer *dns.Server
	tcpServer *dns.Server
	stopCh    chan struct{}
	stopOnce  sync.Once
	sf        singleflight.Group

	// Health and Fallback state
	stateMu          sync.RWMutex
	state            UpstreamState
	consecutiveFails int
	fallbackServers  []string
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:    cfg,
		cache:  make(map[string]cacheItem),
		stopCh: make(chan struct{}),
		state:  StateHealthy,
	}
	s.initHTTPClient()
	return s
}

func (s *Server) initHTTPClient() {
	active := s.cfg.GetActive()
	var bootstrapAddrs []string
	if active != nil && len(active.Bootstrap) > 0 {
		for _, b := range active.Bootstrap {
			if !stringsContainsPort(b) {
				bootstrapAddrs = append(bootstrapAddrs, b+":53")
			} else {
				bootstrapAddrs = append(bootstrapAddrs, b)
			}
		}
	} else {
		bootstrapAddrs = []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}
		if gw := network.GetPhysicalGateway(); gw != "" {
			bootstrapAddrs = append(bootstrapAddrs, gw+":53")
		}
	}

	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	s.transport = &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return dialer.DialContext(ctx, netw, addr)
			}

			// 1. Direct IP or parsed from sslip.io/nip.io (zero DNS queries needed)
			if ip := network.ParseIPFromHostname(host); ip != nil {
				return dialer.DialContext(ctx, netw, net.JoinHostPort(ip.String(), port))
			}

			// 2. Resolve host via bootstrap DNS (including local gateway fallback)
			resolvedIP, err := resolveViaBootstrap(ctx, host, bootstrapAddrs)
			if err == nil && resolvedIP != "" {
				return dialer.DialContext(ctx, netw, net.JoinHostPort(resolvedIP, port))
			}

			return dialer.DialContext(ctx, netw, addr)
		},
	}

	s.client = &http.Client{
		Transport: s.transport,
		Timeout:   4 * time.Second,
	}
}

func stringsContainsPort(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}

func resolveViaBootstrap(ctx context.Context, host string, bootstraps []string) (string, error) {
	if len(bootstraps) == 0 {
		return "", fmt.Errorf("no bootstrap servers provided")
	}

	raceCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)

	type result struct {
		ip  string
		err error
	}
	ch := make(chan result, len(bootstraps))

	for _, b := range bootstraps {
		go func(srv string) {
			c := &dns.Client{
				Net:     "udp",
				Timeout: 1500 * time.Millisecond,
			}
			req := m.Copy()
			resp, _, err := c.ExchangeContext(raceCtx, req, srv)
			if err == nil && resp != nil && len(resp.Answer) > 0 {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						ch <- result{ip: a.A.String(), err: nil}
						return
					}
				}
			}
			if err == nil {
				err = fmt.Errorf("no A record from %s", srv)
			}
			ch <- result{ip: "", err: err}
		}(b)
	}

	var lastErr error
	for i := 0; i < len(bootstraps); i++ {
		select {
		case res := <-ch:
			if res.err == nil && res.ip != "" {
				cancel()
				return res.ip, nil
			}
			lastErr = res.err
		case <-raceCtx.Done():
			if lastErr != nil {
				return "", lastErr
			}
			return "", fmt.Errorf("bootstrap resolution timed out for %s", host)
		}
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("bootstrap resolution failed for %s", host)
}

func (s *Server) getFallbackServers() []string {
	if len(s.fallbackServers) > 0 {
		return s.fallbackServers
	}
	servers := []string{"1.1.1.1:53", "8.8.8.8:53", "77.88.8.8:53"}
	if gw := network.GetPhysicalGateway(); gw != "" {
		servers = append([]string{gw + ":53"}, servers...)
	}
	return servers
}

func isLocalOrCaptive(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	if strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".lan") ||
		strings.HasSuffix(d, ".home") || strings.HasSuffix(d, ".internal") ||
		d == "localhost" {
		return true
	}
	captiveDomains := []string{
		"captive.apple.com",
		"connectivitycheck.gstatic.com",
		"connectivitycheck.android.com",
		"detectportal.firefox.com",
		"msftconnecttest.com",
		"ipv6.msftconnecttest.com",
		"www.msftconnecttest.com",
		"networkcheck.kde.org",
	}
	for _, cd := range captiveDomains {
		if d == cd || strings.HasSuffix(d, "."+cd) {
			return true
		}
	}
	return false
}

func (s *Server) Start() error {
	addr := s.cfg.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:53"
	}

	handler := dns.HandlerFunc(s.handleDNS)

	// 1. Bind UDP socket synchronously to verify port availability immediately
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP port on %s: %w (check if port 53 is already in use by another service/process)", addr, err)
	}
	s.udpServer = &dns.Server{PacketConn: udpConn, Handler: handler}

	// 2. Bind TCP socket synchronously
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("failed to resolve TCP address %s: %w", addr, err)
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("failed to bind TCP port on %s: %w (check if port 53 is already in use by another service/process)", addr, err)
	}
	s.tcpServer = &dns.Server{Listener: tcpListener, Handler: handler}

	log.Printf("[smartnet] DNS server successfully bound to %s (UDP/TCP)", addr)

	// 3. Serve requests in background
	go func() {
		if err := s.udpServer.ActivateAndServe(); err != nil {
			log.Printf("[smartnet] UDP server error: %v", err)
		}
	}()

	go func() {
		if err := s.tcpServer.ActivateAndServe(); err != nil {
			log.Printf("[smartnet] TCP server error: %v", err)
		}
	}()

	// Background cache cleaner
	go s.cleanCacheLoop()

	// Background health checker and auto-recovery
	go s.healthCheckLoop()

	return nil
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.udpServer != nil {
			_ = s.udpServer.Shutdown()
		}
		if s.tcpServer != nil {
			_ = s.tcpServer.Shutdown()
		}
		if s.transport != nil {
			s.transport.CloseIdleConnections()
		}
	})
}

func (s *Server) cleanCacheLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			s.cacheMu.Lock()
			for k, v := range s.cache {
				if now.After(v.expires) {
					delete(s.cache, k)
				}
			}
			s.cacheMu.Unlock()
		}
	}
}

func (s *Server) recordFailure(upstream string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	s.consecutiveFails++
	if s.consecutiveFails >= 3 && s.state == StateHealthy {
		s.state = StateDegraded
		log.Printf("[smartnet] Upstream DoH (%s) failed 3 consecutive times. Switched to automatic fallback mode.", upstream)
	}
}

func (s *Server) recordSuccess(upstream string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if s.state == StateDegraded {
		s.state = StateHealthy
		log.Printf("[smartnet] Primary Upstream DoH (%s) recovered. Restored normal routing.", upstream)
	}
	s.consecutiveFails = 0
}

func (s *Server) healthCheckLoop() {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.stateMu.RLock()
			isDegraded := (s.state == StateDegraded)
			s.stateMu.RUnlock()

			if isDegraded {
				active := s.cfg.GetActive()
				if active == nil || active.Upstream == "" {
					continue
				}
				probe := new(dns.Msg)
				probe.SetQuestion("cloudflare.com.", dns.TypeA)
				resp, err := s.queryDoHWithTimeout(probe, active.Upstream, 2*time.Second)
				if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
					s.recordSuccess(active.Upstream)
				}
			}
		}
	}
}

func (s *Server) queryFallback(r *dns.Msg) (*dns.Msg, error) {
	fallbacks := s.getFallbackServers()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type result struct {
		msg *dns.Msg
		err error
	}
	ch := make(chan result, len(fallbacks))

	for _, target := range fallbacks {
		go func(srv string) {
			c := &dns.Client{
				Net:     "udp",
				Timeout: 1200 * time.Millisecond,
			}
			req := r.Copy()
			resp, _, err := c.ExchangeContext(ctx, req, srv)
			if err == nil && resp != nil {
				ch <- result{msg: resp, err: nil}
			} else {
				ch <- result{msg: nil, err: err}
			}
		}(target)
	}

	var lastErr error
	var lastMsg *dns.Msg
	for i := 0; i < len(fallbacks); i++ {
		select {
		case res := <-ch:
			if res.err == nil && res.msg != nil {
				// Accept success or NXDOMAIN as definitive responses
				if res.msg.Rcode == dns.RcodeSuccess || res.msg.Rcode == dns.RcodeNameError {
					cancel()
					return res.msg, nil
				}
				// Save transient/refusal message but keep waiting for other fallbacks to succeed
				lastMsg = res.msg
			} else if res.err != nil {
				lastErr = res.err
			}
		case <-ctx.Done():
			if lastMsg != nil {
				return lastMsg, nil
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("fallback query timed out")
		}
	}

	if lastMsg != nil {
		return lastMsg, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all fallback resolvers failed")
}

func (s *Server) cacheResponse(cacheKey string, resp *dns.Msg, isFallback bool) {
	if len(resp.Answer) == 0 {
		return
	}
	ttl := uint32(5)
	if !isFallback {
		// Minimum TTL across all records in the response
		minTTL := uint32(3600)
		for _, rr := range resp.Answer {
			if h := rr.Header(); h != nil && h.Ttl < minTTL {
				minTTL = h.Ttl
			}
		}
		for _, rr := range resp.Ns {
			if h := rr.Header(); h != nil && h.Ttl < minTTL {
				minTTL = h.Ttl
			}
		}
		for _, rr := range resp.Extra {
			if h := rr.Header(); h != nil && h.Rrtype != dns.TypeOPT && h.Ttl < minTTL {
				minTTL = h.Ttl
			}
		}
		if minTTL < 5 {
			minTTL = 5
		}
		if minTTL > 3600 {
			minTTL = 3600
		}
		ttl = minTTL
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	// Enforce maximum cache capacity to avoid memory leaks (e.g. DNS water torture attacks)
	if len(s.cache) >= MaxCacheEntries {
		now := time.Now()
		for k, v := range s.cache {
			if now.After(v.expires) {
				delete(s.cache, k)
			}
		}
		// If still at or over capacity, evict 10% of entries
		if len(s.cache) >= MaxCacheEntries {
			evictCount := MaxCacheEntries / 10
			for k := range s.cache {
				delete(s.cache, k)
				evictCount--
				if evictCount <= 0 {
					break
				}
			}
		}
	}

	s.cache[cacheKey] = cacheItem{
		msg:     resp.Copy(),
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	cacheKey := fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)

	// 0. Disable browser DoH canary (e.g. Mozilla Firefox Canary domain)
	// Returning NXDOMAIN instructs browsers to disable internal DoH and use system DNS.
	cleanQName := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if cleanQName == "use-application-dns.net" {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		_ = w.WriteMsg(m)
		return
	}

	active := s.cfg.GetActive()
	var customBypass, customProxy []string
	fakeIPEnabled := false
	if active != nil {
		customBypass = active.BypassDomains
		customProxy = active.ProxyDomains
		fakeIPEnabled = active.FakeIP
	}

	// 1. Split DNS Check: domestic (.ru, banks, gov) & local intranet bypass
	if rules.ShouldBypass(q.Name, customBypass, customProxy) {
		resp, err := s.queryFallback(r)
		if err == nil && resp != nil {
			resp.Id = r.Id
			_ = w.WriteMsg(resp)
			return
		}
	}

	// 2. Fake-IP Handling for non-bypassed target domains
	if fakeIPEnabled {
		if q.Qtype == dns.TypeA {
			fakeIP := fakeip.DefaultPool.Allocate(q.Name)
			if fakeIP != nil {
				m := new(dns.Msg)
				m.SetReply(r)
				m.Authoritative = true
				m.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						A: fakeIP,
					},
				}
				_ = w.WriteMsg(m)
				return
			}
		} else if q.Qtype == dns.TypeAAAA {
			// NODATA for AAAA in Fake-IP mode prevents IPv6 leaks
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			_ = w.WriteMsg(m)
			return
		}
	}

	// 3. Check cache
	s.cacheMu.RLock()
	item, found := s.cache[cacheKey]
	s.cacheMu.RUnlock()

	now := time.Now()
	if found && now.Before(item.expires) {
		remainingSec := uint32(time.Until(item.expires).Seconds())
		if remainingSec < 1 {
			remainingSec = 1
		}
		resp := item.msg.Copy()
		resp.Id = r.Id
		// Adjust TTL of all records to reflect remaining cache lifetime
		for _, rr := range resp.Answer {
			if h := rr.Header(); h != nil && h.Ttl > remainingSec {
				h.Ttl = remainingSec
			}
		}
		for _, rr := range resp.Ns {
			if h := rr.Header(); h != nil && h.Ttl > remainingSec {
				h.Ttl = remainingSec
			}
		}
		for _, rr := range resp.Extra {
			if h := rr.Header(); h != nil && h.Rrtype != dns.TypeOPT && h.Ttl > remainingSec {
				h.Ttl = remainingSec
			}
		}
		_ = w.WriteMsg(resp)
		return
	}

	// 4. Resolve via singleflight deduplication to prevent thundering herds
	type queryResult struct {
		resp *dns.Msg
	}

	val, err, _ := s.sf.Do(cacheKey, func() (any, error) {
		// Double check cache inside singleflight
		s.cacheMu.RLock()
		cached, exists := s.cache[cacheKey]
		s.cacheMu.RUnlock()
		if exists && time.Now().Before(cached.expires) {
			return queryResult{resp: cached.msg.Copy()}, nil
		}

		s.stateMu.RLock()
		currentState := s.state
		s.stateMu.RUnlock()

		var qResp *dns.Msg
		var qErr error
		usedFallback := false

		if currentState == StateHealthy && active != nil && active.Upstream != "" {
			// Normal path: Query Primary DoH with a 2.5s timeout
			qResp, qErr = s.queryDoHWithTimeout(r, active.Upstream, 2500*time.Millisecond)
			if qErr != nil {
				log.Printf("[smartnet] Upstream DoH error for %s (%v)", q.Name, qErr)
				s.recordFailure(active.Upstream)

				// Try secondary DoH if configured
				if active.BackupUpstream != "" {
					backupResp, backupErr := s.queryDoHWithTimeout(r, active.BackupUpstream, 2000*time.Millisecond)
					if backupErr == nil && backupResp != nil {
						qResp = backupResp
					}
				}

				// If secondary DoH also failed or wasn't configured, failover to parallel fallback
				if qResp == nil {
					qResp, qErr = s.queryFallback(r)
					usedFallback = true
					if qErr != nil {
						return nil, qErr
					}
				}
			} else {
				s.recordSuccess(active.Upstream)
			}
		} else {
			// Circuit breaker tripped or no primary profile:
			// Try backup DoH if available before falling back to unencrypted DNS
			if active != nil && active.BackupUpstream != "" {
				qResp, _ = s.queryDoHWithTimeout(r, active.BackupUpstream, 1500*time.Millisecond)
			}
			if qResp == nil {
				// Go straight to fallback to avoid timeout latency
				qResp, qErr = s.queryFallback(r)
				usedFallback = true
				if qErr != nil {
					return nil, qErr
				}
			}
		}

		// Cache response (short 5s TTL for fallback to prevent sticking to Direct IP)
		s.cacheResponse(cacheKey, qResp, usedFallback)
		return queryResult{resp: qResp}, nil
	})

	if err != nil || val == nil {
		log.Printf("[smartnet] DNS resolution failed for %s: %v", q.Name, err)
		dns.HandleFailed(w, r)
		return
	}

	res := val.(queryResult)
	resp := res.resp.Copy()
	resp.Id = r.Id
	_ = w.WriteMsg(resp)
}

func (s *Server) queryDoH(req *dns.Msg, dohURL string) (*dns.Msg, error) {
	return s.queryDoHWithTimeout(req, dohURL, 3*time.Second)
}

func (s *Server) queryDoHWithTimeout(req *dns.Msg, dohURL string, timeout time.Duration) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	u, err := url.Parse(dohURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u.String(),
		bytes.NewReader(wire),
	)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	httpResp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("DoH status %d: %s", httpResp.StatusCode, string(body))
	}

	const maxDNSMessageSize = 65535
	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(respBytes) > maxDNSMessageSize {
		return nil, fmt.Errorf("DoH response exceeded maximum DNS message size (65535 bytes)")
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(respBytes); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return resp, nil
}
