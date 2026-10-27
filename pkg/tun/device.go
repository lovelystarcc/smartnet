package tun

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// Device wraps a WireGuard TUN adapter and manages OS routing for the Fake-IP subnet.
type Device struct {
	tunDev tun.Device
	name   string
	mtu    int
	mu     sync.Mutex
	closed bool
}

func runElevated(name string, args ...string) ([]byte, error) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		cmd := exec.Command(name, args...)
		return cmd.CombinedOutput()
	}
	// Try passwordless sudo first
	cmd := exec.Command("sudo", append([]string{"-n", name}, args...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	// Fall back to direct execution if sudo -n fails
	cmd = exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// CreateDevice allocates a TUN adapter and configures routing for 198.18.0.0/15.
func CreateDevice(mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = 1500
	}

	requestedName := "smartnet"
	if runtime.GOOS == "darwin" {
		// macOS utun driver requires name to be "utun" or "utunX"
		requestedName = "utun"
	}

	dev, err := tun.CreateTUN(requestedName, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	realName, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("failed to get TUN device name: %w", err)
	}

	log.Printf("[smartnet] Allocated TUN device: %s (MTU: %d)", realName, mtu)

	d := &Device{
		tunDev: dev,
		name:   realName,
		mtu:    mtu,
	}

	if err := d.setupRoutes(); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("failed to configure routes for %s: %w", realName, err)
	}

	return d, nil
}

func (d *Device) setupRoutes() error {
	switch runtime.GOOS {
	case "darwin":
		// Configure IP address on point-to-point interface
		if out, err := runElevated("ifconfig", d.name, "198.18.0.1", "198.18.0.1", "netmask", "255.254.0.0", "up"); err != nil {
			return fmt.Errorf("ifconfig failed: %s (%w)", string(out), err)
		}
		// Route 198.18.0.0/15 into utun interface
		if out, err := runElevated("route", "add", "-net", "198.18.0.0/15", "-interface", d.name); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("route add failed: %s (%w)", string(out), err)
			}
		}
		log.Printf("[smartnet] Configured macOS route: 198.18.0.0/15 -> %s", d.name)

	case "linux":
		// Assign IP and bring up interface
		if out, err := runElevated("ip", "addr", "add", "198.18.0.1/15", "dev", d.name); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip addr add failed: %s (%w)", string(out), err)
			}
		}
		if out, err := runElevated("ip", "link", "set", "dev", d.name, "up"); err != nil {
			return fmt.Errorf("ip link set up failed: %s (%w)", string(out), err)
		}
		// Route 198.18.0.0/15 into smartnet interface
		if out, err := runElevated("ip", "route", "add", "198.18.0.0/15", "dev", d.name); err != nil {
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip route add failed: %s (%w)", string(out), err)
			}
		}
		log.Printf("[smartnet] Configured Linux route: 198.18.0.0/15 -> %s", d.name)

	case "windows":
		// Set static IP on adapter
		if out, err := runElevated("netsh", "interface", "ipv4", "set", "address", fmt.Sprintf("name=\"%s\"", d.name), "source=static", "addr=198.18.0.1", "mask=255.254.0.0"); err != nil {
			return fmt.Errorf("netsh set address failed: %s (%w)", string(out), err)
		}
		// Route 198.18.0.0/15
		if out, err := runElevated("route", "add", "198.18.0.0", "mask", "255.254.0.0", "198.18.0.1", "metric", "1"); err != nil {
			return fmt.Errorf("route add failed: %s (%w)", string(out), err)
		}
		log.Printf("[smartnet] Configured Windows route: 198.18.0.0/15 -> %s", d.name)
	}

	return nil
}

func (d *Device) teardownRoutes() {
	switch runtime.GOOS {
	case "darwin":
		_, _ = runElevated("route", "delete", "-net", "198.18.0.0/15")
	case "linux":
		_, _ = runElevated("ip", "route", "del", "198.18.0.0/15", "dev", d.name)
	case "windows":
		_, _ = runElevated("route", "delete", "198.18.0.0")
	}
}

// Name returns the OS interface name (e.g. utun3, smartdns).
func (d *Device) Name() string {
	return d.name
}

// MTU returns the configured MTU.
func (d *Device) MTU() int {
	return d.mtu
}

// Read reads packets from the TUN interface.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.tunDev.Read(bufs, sizes, offset)
}

// Write writes packets to the TUN interface.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	return d.tunDev.Write(bufs, offset)
}

// Close tears down routes and closes the TUN device.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true

	d.teardownRoutes()
	if d.tunDev != nil {
		return d.tunDev.Close()
	}
	return nil
}
