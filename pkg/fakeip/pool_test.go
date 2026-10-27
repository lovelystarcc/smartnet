package fakeip

import (
	"net"
	"testing"
)

func TestPoolAllocationAndLookup(t *testing.T) {
	pool := NewPool()

	domain1 := "chatgpt.com"
	domain2 := "claude.ai"

	ip1 := pool.Allocate(domain1)
	if ip1 == nil {
		t.Fatal("expected non-nil IP")
	}
	if ip1.String() != "198.18.0.2" {
		t.Fatalf("expected first IP to be 198.18.0.2, got %s", ip1)
	}
	if !pool.IsFakeIP(ip1) {
		t.Fatalf("expected %s to be within 198.18.0.0/15", ip1)
	}
	if pool.IsFakeIP(net.ParseIP("198.18.0.1")) {
		t.Fatal("198.18.0.1 should not be considered a Fake-IP (reserved for TUN adapter)")
	}

	// Repeated allocation returns same IP
	ip1Again := pool.Allocate(domain1)
	if !ip1.Equal(ip1Again) {
		t.Fatalf("expected consistent allocation: got %s vs %s", ip1, ip1Again)
	}

	ip2 := pool.Allocate(domain2)
	if ip1.Equal(ip2) {
		t.Fatalf("expected different IPs for different domains: %s vs %s", ip1, ip2)
	}

	// Reverse lookup
	foundDomain1, ok := pool.LookupIP(ip1)
	if !ok || foundDomain1 != domain1 {
		t.Fatalf("expected %s, got %s (ok=%v)", domain1, foundDomain1, ok)
	}

	foundDomain2, ok := pool.LookupIP(ip2)
	if !ok || foundDomain2 != domain2 {
		t.Fatalf("expected %s, got %s (ok=%v)", domain2, foundDomain2, ok)
	}

	// Forward lookup
	foundIP, ok := pool.LookupDomain(domain1)
	if !ok || !foundIP.Equal(ip1) {
		t.Fatalf("expected %s, got %s (ok=%v)", ip1, foundIP, ok)
	}

	// Non-fake IP lookup
	realIP := net.ParseIP("8.8.8.8")
	if pool.IsFakeIP(realIP) {
		t.Errorf("8.8.8.8 should not be Fake-IP")
	}
	if _, ok := pool.LookupIP(realIP); ok {
		t.Errorf("LookupIP on real IP should return false")
	}

	alloc, total := pool.Stats()
	if alloc != 2 || total <= 0 {
		t.Errorf("unexpected stats: alloc=%d, total=%d", alloc, total)
	}

	pool.Clear()
	allocAfter, _ := pool.Stats()
	if allocAfter != 0 {
		t.Errorf("expected 0 allocated after clear, got %d", allocAfter)
	}
}
