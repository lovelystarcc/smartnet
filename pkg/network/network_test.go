package network

import (
	"testing"
)

func TestParseIPFromHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.1.1.1", "1.1.1.1"},
		{"2.26.227.147", "2.26.227.147"},
		{"2-26-227-147.sslip.io", "2.26.227.147"},
		{"192-168-1-1.nip.io", "192.168.1.1"},
		{"example.com", ""},
	}

	for _, tt := range tests {
		ip := ParseIPFromHostname(tt.input)
		if tt.expected == "" {
			if ip != nil {
				t.Errorf("ParseIPFromHostname(%q) = %v; want nil", tt.input, ip)
			}
		} else {
			if ip == nil || ip.String() != tt.expected {
				t.Errorf("ParseIPFromHostname(%q) = %v; want %s", tt.input, ip, tt.expected)
			}
		}
	}
}

func TestActiveInterface(t *testing.T) {
	iface, err := ActiveInterface()
	if err != nil {
		t.Fatalf("ActiveInterface failed: %v", err)
	}
	if iface == "" {
		t.Fatal("expected non-empty active interface name")
	}
}

func TestGetPublicIP(t *testing.T) {
	info, err := GetPublicIP()
	if err != nil {
		t.Logf("GetPublicIP returned error (might be offline): %v", err)
		return
	}
	if info == nil || info.IP == "" {
		t.Errorf("expected non-empty IP, got %v", info)
	}
}

func TestDecodeOEM(t *testing.T) {
	// Standard ASCII
	ascii := []byte("Hello world")
	if decodeOEM(ascii) != "Hello world" {
		t.Errorf("expected 'Hello world', got %q", decodeOEM(ascii))
	}

	// Valid UTF-8 Russian
	utf8Ru := []byte("Привет мир")
	if decodeOEM(utf8Ru) != "Привет мир" {
		t.Errorf("expected 'Привет мир', got %q", decodeOEM(utf8Ru))
	}

	// CP866 bytes for "Беспроводная сеть"
	// Б=0x81, е=0xA5, с=0xE1, п=0xAF, р=0xE0, о=0xAE, в=0xA2, о=0xAE, д=0xA4, н=0xAD, а=0xA0, я=0xEF,
	//  =0x20, с=0xE1, е=0xA5, т=0xE2, ь=0xEC
	cp866Bytes := []byte{0x81, 0xA5, 0xE1, 0xAF, 0xE0, 0xAE, 0xA2, 0xAE, 0xA4, 0xAD, 0xA0, 0xEF, ' ', 0xE1, 0xA5, 0xE2, 0xEC}
	decoded := decodeOEM(cp866Bytes)
	if decoded != "Беспроводная сеть" {
		t.Errorf("expected 'Беспроводная сеть', got %q", decoded)
	}
}

func TestEscapePowerShellString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Wi-Fi", "Wi-Fi"},
		{"Timur's iPhone", "Timur''s iPhone"},
		{"Adapter's 'Special' Net", "Adapter''s ''Special'' Net"},
		{"Normal_Ethernet", "Normal_Ethernet"},
	}

	for _, tt := range tests {
		got := escapePowerShellString(tt.input)
		if got != tt.expected {
			t.Errorf("escapePowerShellString(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

