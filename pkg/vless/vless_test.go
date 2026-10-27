package vless

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"smartnet/pkg/config"
)

func TestParseURL(t *testing.T) {
	raw := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@vpn.example.com:8443?encryption=none&security=reality&sni=gateway.icloud.com&pbk=fakePubkey123&sid=1234abcd#Germany"
	cfg, err := ParseURL(raw)
	if err != nil {
		t.Fatalf("ParseURL failed: %v", err)
	}

	if cfg.Server != "vpn.example.com" {
		t.Errorf("Expected server vpn.example.com, got %s", cfg.Server)
	}
	if cfg.Port != 8443 {
		t.Errorf("Expected port 8443, got %d", cfg.Port)
	}
	if cfg.UUID != "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d" {
		t.Errorf("Expected UUID, got %s", cfg.UUID)
	}
	if cfg.ServerName != "gateway.icloud.com" {
		t.Errorf("Expected SNI gateway.icloud.com, got %s", cfg.ServerName)
	}
	if cfg.PublicKey != "fakePubkey123" {
		t.Errorf("Expected pbk fakePubkey123, got %s", cfg.PublicKey)
	}
	if cfg.ShortID != "1234abcd" {
		t.Errorf("Expected sid 1234abcd, got %s", cfg.ShortID)
	}

	// Unsupported flow should be explicitly rejected
	visionURL := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@vpn.example.com:8443?security=reality&sni=gateway.icloud.com&pbk=fakePubkey123&flow=xtls-rprx-vision"
	if _, err := ParseURL(visionURL); err == nil {
		t.Error("Expected error for unsupported flow xtls-rprx-vision")
	}

	// Overlong short_id (> 16 hex chars) should be rejected
	longSidURL := "vless://a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d@vpn.example.com:8443?security=reality&sni=gateway.icloud.com&pbk=fakePubkey123&sid=1234567890abcdef12"
	if _, err := ParseURL(longSidURL); err == nil {
		t.Error("Expected error for overlong short_id > 16 hex chars")
	}

	// Invalid URLs
	if _, err := ParseURL("https://example.com"); err == nil {
		t.Error("Expected error for non-vless scheme")
	}
	if _, err := ParseURL("vless://@vpn.example.com:443"); err == nil {
		t.Error("Expected error for missing UUID")
	}
	if _, err := ParseURL("vless://uuid@:443"); err == nil {
		t.Error("Expected error for missing server")
	}
}

func TestBuildRequestHeader(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"

	// 1. IPv4 target
	hdr, err := buildRequestHeader(uuid, 0x01, "1.2.3.4:443")
	if err != nil {
		t.Fatalf("buildRequestHeader IPv4 failed: %v", err)
	}
	if hdr[0] != 0x00 { // version
		t.Errorf("Expected version 0, got %d", hdr[0])
	}
	cleanUUID := "a1b2c3d4e5f67a8b9c0d1e2f3a4b5c6d"
	expectedUUID, _ := hex.DecodeString(cleanUUID)
	if string(hdr[1:17]) != string(expectedUUID) {
		t.Errorf("UUID bytes mismatch")
	}
	if hdr[18] != 0x01 { // command TCP
		t.Errorf("Expected command 1, got %d", hdr[18])
	}
	port := binary.BigEndian.Uint16(hdr[19:21])
	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}
	if hdr[21] != 0x01 { // IPv4 type
		t.Errorf("Expected addr type 1, got %d", hdr[21])
	}

	// 2. Domain target
	hdrDomain, err := buildRequestHeader(uuid, 0x01, "example.com:80")
	if err != nil {
		t.Fatalf("buildRequestHeader domain failed: %v", err)
	}
	if hdrDomain[21] != 0x02 { // domain type
		t.Errorf("Expected addr type 2, got %d", hdrDomain[21])
	}
	domLen := int(hdrDomain[22])
	if domLen != len("example.com") {
		t.Errorf("Expected domain length %d, got %d", len("example.com"), domLen)
	}
	if string(hdrDomain[23:23+domLen]) != "example.com" {
		t.Errorf("Domain string mismatch")
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SmartNet Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func TestTLSRejectsUntrustedServer(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portNum, _ := strconv.Atoi(portStr)

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	vlessCfg := &config.VLESSConfig{
		Server:     "127.0.0.1",
		Port:       portNum,
		UUID:       "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
		ServerName: "127.0.0.1",
	}

	// Default dialer without custom RootCAs must reject untrusted self-signed certificate
	dialer := NewDialer(vlessCfg)
	_, err = dialer.Dial("tcp", "target-domain.com:443")
	if err == nil {
		t.Fatal("Expected dial to fail certificate verification against untrusted server, but it succeeded")
	}
}

func TestVLESSDialerEndToEnd(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse test certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portNum, _ := strconv.Atoi(portStr)

	// Mock VLESS Server
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read VLESS request header (min 22 bytes)
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil || n < 22 {
			return
		}

		// Send VLESS response header (version 0, addon len 0)
		_, _ = conn.Write([]byte{0x00, 0x00})

		// Echo back payload
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, _ = conn.Write(append([]byte("vless-echo:"), buf[:n]...))
		}
	}()

	vlessCfg := &config.VLESSConfig{
		Server:     "127.0.0.1",
		Port:       portNum,
		UUID:       "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
		ServerName: "127.0.0.1",
	}

	dialer := NewDialer(vlessCfg)
	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)
	dialer.rootCAs = certPool

	clientConn, err := dialer.Dial("tcp", "target-domain.com:443")
	if err != nil {
		t.Fatalf("Dialer.Dial failed: %v", err)
	}
	defer clientConn.Close()

	// Send message through tunnel
	_, err = clientConn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	readBuf := make([]byte, 64)
	n, err := clientConn.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(readBuf[:n]) != "vless-echo:ping" {
		t.Errorf("Expected vless-echo:ping, got %s", string(readBuf[:n]))
	}
}

func TestVLESSUDPFraming(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	vConn := &vlessConn{
		Conn:  clientConn,
		isUDP: true,
	}

	go func() {
		// Server reads 2-byte datagram length prefix + payload
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
			return
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)
		if pktLen != 4 {
			t.Errorf("Expected UDP length 4, got %d", pktLen)
			return
		}
		payload := make([]byte, pktLen)
		if _, err := io.ReadFull(serverConn, payload); err != nil {
			return
		}
		if string(payload) != "ping" {
			t.Errorf("Expected ping, got %s", string(payload))
			return
		}

		// Server writes VLESS response header (version 0, addon 0)
		_, _ = serverConn.Write([]byte{0x00, 0x00})
		// Server writes 2-byte length + payload "pong" (00 04 pong)
		respFrame := []byte{0x00, 0x04, 'p', 'o', 'n', 'g'}
		_, _ = serverConn.Write(respFrame)
	}()

	// Write UDP datagram "ping"
	n, err := vConn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("Write UDP failed: %v", err)
	}
	if n != 4 {
		t.Errorf("Expected 4 bytes written, got %d", n)
	}

	// Read UDP datagram "pong"
	buf := make([]byte, 65535)
	rn, err := vConn.Read(buf)
	if err != nil {
		t.Fatalf("Read UDP failed: %v", err)
	}
	if rn != 4 || string(buf[:rn]) != "pong" {
		t.Errorf("Expected pong (4 bytes), got %s (%d bytes)", string(buf[:rn]), rn)
	}
}

func TestRealityRejectsRogueServer(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portNum, _ := strconv.Atoi(portStr)

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKeyBase64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	vlessCfg := &config.VLESSConfig{
		Server:     "127.0.0.1",
		Port:       portNum,
		UUID:       "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
		ServerName: "127.0.0.1",
		PublicKey:  pubKeyBase64,
	}

	dialer := NewDialer(vlessCfg)
	_, err = dialer.Dial("tcp", "target-domain.com:443")
	if err == nil {
		t.Fatal("Expected Reality handshake with unauthenticated rogue server to fail, but it succeeded")
	}
}

func TestUDPStreaming_EmptyPacketSkipped(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	vConn := &vlessConn{
		Conn:  clientConn,
		isUDP: true,
	}

	go func() {
		// Server writes VLESS response header (00 00)
		_, _ = serverConn.Write([]byte{0x00, 0x00})
		// Server sends empty packet (00 00)
		_, _ = serverConn.Write([]byte{0x00, 0x00})
		// Then server sends datagram "hello" (00 05 hello)
		respFrame := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
		_, _ = serverConn.Write(respFrame)
	}()

	buf := make([]byte, 64)
	n, err := vConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("Expected 5 bytes 'hello', got %d bytes %q", n, string(buf[:n]))
	}

	// Verify CloseWrite does not panic
	if err := vConn.CloseWrite(); err != nil {
		t.Logf("CloseWrite on pipe conn: %v", err)
	}
}
