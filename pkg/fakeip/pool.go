package fakeip

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// RFC 2544 / RFC 6598 Benchmark testing range commonly used for Fake-IP.
	// 198.18.0.1 is reserved as the TUN adapter interface IP, so the pool starts at 198.18.0.2.
	fakeIPStartUint = uint32(0xC6120002) // 198.18.0.2
	fakeIPEndUint   = uint32(0xC613FFFE) // 198.19.255.254
	fakeIPPoolSize  = fakeIPEndUint - fakeIPStartUint + 1
)

var fakeIPNet = &net.IPNet{
	IP:   net.IPv4(198, 18, 0, 0),
	Mask: net.CIDRMask(15, 32),
}

// Pool provides thread-safe bidirectional Fake-IP mapping
type Pool struct {
	mu            sync.RWMutex
	domainToIP    map[string]uint32
	ipToDomain    map[uint32]string
	currentOffset uint32
}

var DefaultPool = NewPool()

func NewPool() *Pool {
	return &Pool{
		domainToIP: make(map[string]uint32),
		ipToDomain: make(map[uint32]string),
	}
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func cleanDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

// IsFakeIP checks if the given IP belongs to the 198.18.0.0/15 Fake-IP range (excluding the adapter IP 198.18.0.1)
func (p *Pool) IsFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 198 && v4[1] == 18 && v4[2] == 0 && v4[3] == 1 {
		return false // Reserved adapter interface IP
	}
	return fakeIPNet.Contains(v4)
}

// Allocate assigns or retrieves a Fake-IP for the given domain
func (p *Pool) Allocate(domain string) net.IP {
	d := cleanDomain(domain)
	if d == "" {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Return existing allocation
	if ipUint, found := p.domainToIP[d]; found {
		return uint32ToIP(ipUint)
	}

	// Allocate next IP in circular buffer
	ipUint := fakeIPStartUint + p.currentOffset
	p.currentOffset = (p.currentOffset + 1) % fakeIPPoolSize

	// Evict existing mapping on collision / pool wrap
	if oldDomain, occupied := p.ipToDomain[ipUint]; occupied {
		delete(p.domainToIP, oldDomain)
	}

	p.domainToIP[d] = ipUint
	p.ipToDomain[ipUint] = d

	return uint32ToIP(ipUint)
}

// LookupIP finds the original domain for a Fake-IP
func (p *Pool) LookupIP(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil || !p.IsFakeIP(v4) {
		return "", false
	}

	ipUint := ipToUint32(v4)

	p.mu.RLock()
	defer p.mu.RUnlock()

	domain, found := p.ipToDomain[ipUint]
	return domain, found
}

// LookupDomain finds the allocated Fake-IP for a domain if it exists
func (p *Pool) LookupDomain(domain string) (net.IP, bool) {
	d := cleanDomain(domain)
	if d == "" {
		return nil, false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	ipUint, found := p.domainToIP[d]
	if !found {
		return nil, false
	}
	return uint32ToIP(ipUint), true
}

// Stats returns count of allocated IPs and total pool size
func (p *Pool) Stats() (allocated int, total int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.domainToIP), int(fakeIPPoolSize)
}

// Clear resets all allocated mappings
func (p *Pool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.domainToIP = make(map[string]uint32)
	p.ipToDomain = make(map[uint32]string)
	p.currentOffset = 0
}

// QueryDaemonStats queries the running daemon proxy for active Fake-IP pool statistics.
func QueryDaemonStats(proxyAddr string) (int, int, error) {
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:7890"
	}
	client := &http.Client{Timeout: 800 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/_smartnet/fakeip/stats", nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("X-SmartNet-Local", "1")

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("daemon responded with HTTP %d", resp.StatusCode)
	}
	var data struct {
		Allocated int `json:"allocated"`
		Total     int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, 0, err
	}
	return data.Allocated, data.Total, nil
}

// ClearDaemon sends a request to the running daemon proxy to flush its active Fake-IP mappings.
func ClearDaemon(proxyAddr string) error {
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:7890"
	}
	client := &http.Client{Timeout: 800 * time.Millisecond}
	req, err := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/_smartnet/fakeip/clear", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-SmartNet-Local", "1")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon responded with HTTP %d", resp.StatusCode)
	}
	return nil
}
