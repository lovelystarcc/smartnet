package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"smartnet/pkg/config"
	"smartnet/pkg/fakeip"
	"smartnet/pkg/vless"

	"golang.org/x/net/proxy"
)

type bufferedConn struct {
	r io.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type Server struct {
	cfg      *config.Config
	listener net.Listener
	stopCh   chan struct{}
	mu       sync.Mutex
}

func New(cfg *config.Config) *Server {
	return &Server{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (s *Server) Start() error {
	addr := s.cfg.ProxyAddr
	if addr == "" {
		addr = "127.0.0.1:7890"
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	log.Printf("[smartnet] Proxy bridge listening on %s (Mixed HTTP/SOCKS5)", addr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					continue
				}
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}
}

// Dial connects to the target address, resolving Fake-IPs to original domains
// and routing through the upstream proxy if configured.
func Dial(cfg *config.Config, network, target string) (net.Conn, error) {
	// If target is in Fake-IP format (e.g. 198.18.0.1:443), restore original domain
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil && fakeip.DefaultPool.IsFakeIP(ip) {
			if realDomain, found := fakeip.DefaultPool.LookupIP(ip); found {
				target = net.JoinHostPort(realDomain, port)
			}
		}
	}

	if cfg != nil {
		active := cfg.GetActive()
		if active != nil {
			// If VPN mode is active and VLESS is configured, tunnel through VLESS-Reality!
			if active.VPN && active.VLESS != nil {
				d := vless.NewDialer(active.VLESS)
				return d.Dial(network, target)
			}

			// If proxy upstream is configured, route through SOCKS5
			if network == "tcp" && active.ProxyUpstream != "" {
				u, err := url.Parse(active.ProxyUpstream)
				if err == nil {
					dialer, err := proxy.FromURL(u, proxy.Direct)
					if err == nil {
						return dialer.Dial("tcp", target)
					}
				}
			}
		}
	}

	d := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return d.Dial(network, target)
}

func (s *Server) dial(target string) (net.Conn, error) {
	return Dial(s.cfg, "tcp", target)
}

func (s *Server) handleConnection(rawConn net.Conn) {
	br := bufio.NewReader(rawConn)
	firstByte, err := br.Peek(1)
	if err != nil {
		_ = rawConn.Close()
		return
	}

	// SOCKS5 starts with byte 0x05
	if firstByte[0] == 0x05 {
		s.handleSOCKS5(rawConn, br)
	} else {
		s.handleHTTP(rawConn, br)
	}
}

func (s *Server) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	// 1. Handshake: Version (1 byte), NMethods (1 byte), Methods (N bytes)
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		_ = conn.Close()
		return
	}

	nMethods, err := br.ReadByte()
	if err != nil {
		_ = conn.Close()
		return
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		_ = conn.Close()
		return
	}

	// Reply NO AUTH (0x05, 0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		_ = conn.Close()
		return
	}

	// 2. Request: VER (1), CMD (1), RSV (1), ATYP (1), ADDR (variable), PORT (2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		_ = conn.Close()
		return
	}

	if header[1] != 0x01 { // CMD != CONNECT
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		ipv4 := make([]byte, 4)
		if _, err := io.ReadFull(br, ipv4); err != nil {
			_ = conn.Close()
			return
		}
		host = net.IP(ipv4).String()
	case 0x03: // Domain name
		nameLen, err := br.ReadByte()
		if err != nil {
			_ = conn.Close()
			return
		}
		domain := make([]byte, nameLen)
		if _, err := io.ReadFull(br, domain); err != nil {
			_ = conn.Close()
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadFull(br, ipv6); err != nil {
			_ = conn.Close()
			return
		}
		host = net.IP(ipv6).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		_ = conn.Close()
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	destConn, err := s.dial(target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	// Success response: 0x05, 0x00, 0x00, 0x01, bind_addr(0.0.0.0:0)
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = destConn.Close()
		_ = conn.Close()
		return
	}

	clientConn := &bufferedConn{r: br, Conn: conn}
	pipe(clientConn, destConn)
}

func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = conn.Close()
		return
	}

	// Internal control endpoints for daemon management (Fake-IP stats, cache clear, etc.)
	if strings.HasPrefix(req.URL.Path, "/_smartnet/") {
		switch req.URL.Path {
		case "/_smartnet/fakeip/stats":
			alloc, total := fakeip.DefaultPool.Stats()
			resp := fmt.Sprintf(`{"allocated":%d,"total":%d}`, alloc, total)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(resp)) + "\r\nConnection: close\r\n\r\n" + resp))
			_ = conn.Close()
			return
		case "/_smartnet/fakeip/clear":
			fakeip.DefaultPool.Clear()
			resp := `{"status":"ok"}`
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(resp)) + "\r\nConnection: close\r\n\r\n" + resp))
			_ = conn.Close()
			return
		default:
			_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"))
			_ = conn.Close()
			return
		}
	}

	if req.Method == http.MethodConnect {
		target := req.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}

		destConn, err := s.dial(target)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			_ = conn.Close()
			return
		}

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			_ = destConn.Close()
			_ = conn.Close()
			return
		}

		clientConn := &bufferedConn{r: br, Conn: conn}
		pipe(clientConn, destConn)
		return
	}

	// Standard plain HTTP proxy (e.g. GET http://example.com/foo HTTP/1.1)
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	destConn, err := s.dial(target)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		_ = conn.Close()
		return
	}

	_ = req.Write(destConn)
	clientConn := &bufferedConn{r: br, Conn: conn}
	pipe(clientConn, destConn)
}

func pipe(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c1, c2)
		_ = c1.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c2, c1)
		_ = c2.Close()
	}()

	wg.Wait()
}

// IsListening checks if local proxy port is active
func IsListening(addr string) bool {
	if addr == "" {
		addr = "127.0.0.1:7890"
	}
	conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
}
