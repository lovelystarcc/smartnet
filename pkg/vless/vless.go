package vless

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"

	"smartnet/pkg/config"
)

// ParseURL parses a vless:// URI into a VLESSConfig.
// Format: vless://uuid@server:port?encryption=none&security=reality&sni=sni.domain&pbk=public_key&sid=short_id&flow=xtls-rprx-vision#name
func ParseURL(rawURL string) (*config.VLESSConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS URL: %w", err)
	}

	if u.Scheme != "vless" {
		return nil, fmt.Errorf("unsupported scheme %q (expected vless://)", u.Scheme)
	}

	uuidStr := u.User.Username()
	if uuidStr == "" {
		return nil, fmt.Errorf("missing UUID in VLESS URL")
	}

	server := u.Hostname()
	if server == "" {
		return nil, fmt.Errorf("missing server host in VLESS URL")
	}

	portStr := u.Port()
	if portStr == "" {
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q in VLESS URL", portStr)
	}

	q := u.Query()
	cfg := &config.VLESSConfig{
		Server:     server,
		Port:       port,
		UUID:       uuidStr,
		Flow:       q.Get("flow"),
		ServerName: q.Get("sni"),
		PublicKey:  q.Get("pbk"),
		ShortID:    q.Get("sid"),
		SpiderX:    q.Get("spx"),
	}

	if cfg.Flow != "" && cfg.Flow != "none" {
		return nil, fmt.Errorf("unsupported VLESS flow %q: xtls-rprx-vision is not supported, configure VLESS without flow", cfg.Flow)
	}

	if len(cfg.ShortID) > 16 {
		return nil, fmt.Errorf("invalid reality short_id %q: maximum length is 16 hex characters (8 bytes)", cfg.ShortID)
	}

	if cfg.ServerName == "" {
		cfg.ServerName = server
	}

	return cfg, nil
}

// Dialer establishes outbound connections over VLESS-Reality.
type Dialer struct {
	cfg     *config.VLESSConfig
	rootCAs *x509.CertPool
}

// NewDialer creates a new VLESS dialer.
func NewDialer(cfg *config.VLESSConfig) *Dialer {
	return &Dialer{cfg: cfg}
}

// Dial connects to target (host:port) through the VLESS server.
func (d *Dialer) Dial(network, target string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, target)
}

// DialContext connects to target through the VLESS server with context.
func (d *Dialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	serverAddr := net.JoinHostPort(d.cfg.Server, strconv.Itoa(d.cfg.Port))

	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to VLESS server %s: %w", serverAddr, err)
	}

	var tlsConn net.Conn
	if d.cfg.PublicKey != "" {
		tlsConn, err = realityHandshake(ctx, rawConn, d.cfg)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}
	} else {
		tlsConfig := &tls.Config{
			ServerName:         d.cfg.ServerName,
			InsecureSkipVerify: false,
			RootCAs:            d.rootCAs,
		}
		stdConn := tls.Client(rawConn, tlsConfig)
		if err := stdConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("VLESS TLS handshake failed with %s: %w", d.cfg.ServerName, err)
		}
		tlsConn = stdConn
	}

	// Build and send VLESS request header
	isUDP := strings.HasPrefix(network, "udp")
	cmd := byte(0x01) // TCP
	if isUDP {
		cmd = byte(0x02) // UDP
	}

	hdr, err := buildRequestHeader(d.cfg.UUID, cmd, target)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("failed to build VLESS header: %w", err)
	}

	if _, err := tlsConn.Write(hdr); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("failed to send VLESS header: %w", err)
	}

	return &vlessConn{Conn: tlsConn, isUDP: isUDP}, nil
}

type closeWriter interface {
	CloseWrite() error
}

type vlessConn struct {
	net.Conn
	mu           sync.Mutex
	writeMu      sync.Mutex
	headerRead   bool
	isUDP        bool
	udpBuf       []byte
	closeWritten bool
}

func (c *vlessConn) CloseWrite() error {
	c.mu.Lock()
	c.closeWritten = true
	c.mu.Unlock()

	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
}

func (c *vlessConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if !c.headerRead {
		respHdr := make([]byte, 2)
		if _, err := io.ReadFull(c.Conn, respHdr); err != nil {
			c.mu.Unlock()
			return 0, fmt.Errorf("failed to read VLESS response header: %w", err)
		}
		if respHdr[0] != 0x00 {
			c.mu.Unlock()
			return 0, fmt.Errorf("unsupported VLESS response version: %d", respHdr[0])
		}
		addonLen := int(respHdr[1])
		if addonLen > 0 {
			addonBuf := make([]byte, addonLen)
			if _, err := io.ReadFull(c.Conn, addonBuf); err != nil {
				c.mu.Unlock()
				return 0, fmt.Errorf("failed to read VLESS addon bytes: %w", err)
			}
		}
		c.headerRead = true
	}
	closeWritten := c.closeWritten
	c.mu.Unlock()

	if closeWritten {
		_ = c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}

	if !c.isUDP {
		return c.Conn.Read(b)
	}

	if len(b) == 0 {
		return 0, nil
	}

	for {
		c.mu.Lock()
		if len(c.udpBuf) > 0 {
			n := copy(b, c.udpBuf)
			c.udpBuf = c.udpBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		// Read 2-byte datagram length prefix
		var lenBuf [2]byte
		if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
			return 0, err
		}
		packetLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if packetLen == 0 {
			continue
		}

		packet := make([]byte, packetLen)
		if _, err := io.ReadFull(c.Conn, packet); err != nil {
			return 0, err
		}

		c.mu.Lock()
		if c.closeWritten {
			_ = c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
		n := copy(b, packet)
		if n < packetLen {
			c.udpBuf = packet[n:]
		}
		c.mu.Unlock()
		return n, nil
	}
}

func (c *vlessConn) Write(b []byte) (int, error) {
	if !c.isUDP {
		return c.Conn.Write(b)
	}

	if len(b) > 0xFFFF {
		return 0, fmt.Errorf("UDP packet exceeds 65535 bytes: %d", len(b))
	}

	// UDP framing: 2-byte big-endian length prefix followed by datagram payload
	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(b)))
	copy(frame[2:], b)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var written int
	for written < len(frame) {
		n, err := c.Conn.Write(frame[written:])
		if err != nil {
			return 0, err
		}
		written += n
	}
	return len(b), nil
}

func parseUUID(uuidStr string) ([]byte, error) {
	clean := strings.ReplaceAll(uuidStr, "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("UUID must be 32 hex chars, got %d", len(clean))
	}
	return hex.DecodeString(clean)
}

func buildRequestHeader(uuidStr string, cmd byte, target string) ([]byte, error) {
	uuidBytes, err := parseUUID(uuidStr)
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	var buf bytes.Buffer
	buf.WriteByte(0x00) // VLESS version 0
	buf.Write(uuidBytes) // 16 bytes UUID
	buf.WriteByte(0x00) // Addon length 0
	buf.WriteByte(cmd)  // 0x01 = TCP, 0x02 = UDP

	// Port (2 bytes BigEndian)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	buf.Write(portBytes[:])

	// Address Type & Address
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf.WriteByte(0x01) // IPv4
			buf.Write(v4)
		} else {
			buf.WriteByte(0x03) // IPv6
			buf.Write(ip.To16())
		}
	} else {
		// Domain
		buf.WriteByte(0x02) // Domain
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}

	return buf.Bytes(), nil
}

func realityHandshake(ctx context.Context, rawConn net.Conn, cfg *config.VLESSConfig) (net.Conn, error) {
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(cfg.PublicKey)
	if err != nil {
		pubKeyBytes, err = base64.URLEncoding.DecodeString(cfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid reality public key base64: %w", err)
		}
	}
	var shortIDBytes []byte
	if cfg.ShortID != "" {
		shortIDBytes, err = hex.DecodeString(cfg.ShortID)
		if err != nil {
			return nil, fmt.Errorf("invalid reality short_id hex: %w", err)
		}
		if len(shortIDBytes) > 8 {
			return nil, fmt.Errorf("reality short_id exceeds 8 bytes (16 hex characters): got %d bytes", len(shortIDBytes))
		}
	}

	var verified bool
	authKey := make([]byte, 32)

	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:             cfg.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("reality: no peer certificate presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("reality: failed to parse peer certificate: %w", err)
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("reality: server certificate public key is not ed25519; server authentication failed")
			}
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			if !bytes.Equal(h.Sum(nil), cert.Signature) {
				return fmt.Errorf("reality: certificate signature mismatch; server authentication failed")
			}
			verified = true
			return nil
		},
	}, utls.HelloChrome_Auto)

	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("failed to build uTLS handshake state: %w", err)
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // Clear AAD in raw ClientHello

	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 0
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	if len(shortIDBytes) > 0 {
		copy(hello.SessionId[8:16], shortIDBytes)
	}

	publicKey, err := ecdh.X25519().NewPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid x25519 public key: %w", err)
	}

	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, fmt.Errorf("ecdhe keys not found in TLS 1.3 ClientHello")
	}

	sharedKey, err := ecdhe.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("reality ECDH exchange failed: %w", err)
	}

	if _, err := hkdf.New(sha256.New, sharedKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, fmt.Errorf("reality HKDF key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("reality AES cipher init failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality GCM init failed: %w", err)
	}

	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("reality TLS handshake failed with %s: %w", cfg.ServerName, err)
	}
	if !verified {
		return nil, fmt.Errorf("reality: server authentication failed")
	}
	return uConn, nil
}
