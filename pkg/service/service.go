package service

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"smartnet/pkg/config"
	"smartnet/pkg/network"

	"github.com/miekg/dns"
)

const (
	MacPlistPath = "/Library/LaunchDaemons/com.smartnet.daemon.plist"
	MacLabel     = "com.smartnet.daemon"
	LinuxUnit    = "/etc/systemd/system/smartnet.service"

	LegacyMacPlistPath = "/Library/LaunchDaemons/com.smartdns.daemon.plist"
	LegacyMacLabel     = "com.smartdns.daemon"
	LegacyLinuxUnit    = "/etc/systemd/system/smartdns.service"
)

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
	// Only prompt interactively if sudo reported password is required
	outStr := string(out)
	if strings.Contains(outStr, "password is required") || strings.Contains(outStr, "a password is required") {
		cmd = exec.Command("sudo", append([]string{name}, args...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = nil
		return nil, cmd.Run()
	}
	return out, err
}

func Install(binPath string) error {
	absBin, err := filepath.Abs(binPath)
	if err != nil {
		absBin = binPath
	}

	if runtime.GOOS == "darwin" {
		// Clean up legacy smartdns daemon first if present
		if _, err := os.Stat(LegacyMacPlistPath); err == nil {
			_, _ = runElevated("launchctl", "bootout", "system/"+LegacyMacLabel)
			_, _ = runElevated("launchctl", "unload", LegacyMacPlistPath)
			_, _ = runElevated("rm", "-f", LegacyMacPlistPath)
		}

		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/smartnet.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/smartnet.err</string>
</dict>
</plist>
`, MacLabel, absBin)

		tmpDir, err := os.MkdirTemp("", "smartnet-svc-*")
		if err != nil {
			return fmt.Errorf("failed to create secure temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		tmpFile := filepath.Join(tmpDir, "daemon.plist")
		if err := os.WriteFile(tmpFile, []byte(plistContent), 0600); err != nil {
			return err
		}

		script := fmt.Sprintf("cp %s %s && chown root:wheel %s && chmod 644 %s",
			tmpFile, MacPlistPath, MacPlistPath, MacPlistPath)
		if _, err := runElevated("sh", "-c", script); err != nil {
			return fmt.Errorf("failed to install plist: %w", err)
		}

		return Start()
	}

	if runtime.GOOS == "linux" {
		// Clean up legacy smartdns unit if present
		_, _ = runElevated("systemctl", "disable", "--now", "smartdns")
		_, _ = runElevated("rm", "-f", LegacyLinuxUnit)

		unitContent := fmt.Sprintf(`[Unit]
Description=SmartNet Daemon (DoH / Transparent Proxy / VLESS Tunnel)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, absBin)

		tmpDir, err := os.MkdirTemp("", "smartnet-svc-*")
		if err != nil {
			return fmt.Errorf("failed to create secure temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		tmpFile := filepath.Join(tmpDir, "smartnet.service")
		if err := os.WriteFile(tmpFile, []byte(unitContent), 0600); err != nil {
			return err
		}

		script := fmt.Sprintf("cp %s %s && chmod 644 %s && systemctl daemon-reload && systemctl enable --now smartnet",
			tmpFile, LinuxUnit, LinuxUnit)
		if _, err := runElevated("sh", "-c", script); err != nil {
			return fmt.Errorf("failed to install systemd unit: %w", err)
		}
		return nil
	}

	if runtime.GOOS == "windows" {
		return windowsInstall(absBin)
	}

	return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

func Uninstall() error {
	_ = Stop()
	if runtime.GOOS == "darwin" {
		_, _ = runElevated("rm", "-f", LegacyMacPlistPath)
		_, err := runElevated("rm", "-f", MacPlistPath)
		return err
	}
	if runtime.GOOS == "linux" {
		_, _ = runElevated("sh", "-c", fmt.Sprintf("systemctl disable --now smartdns && rm -f %s", LegacyLinuxUnit))
		script := fmt.Sprintf("systemctl disable --now smartnet && rm -f %s && systemctl daemon-reload", LinuxUnit)
		_, err := runElevated("sh", "-c", script)
		return err
	}
	if runtime.GOOS == "windows" {
		return windowsUninstall()
	}
	return nil
}

func Start() error {
	if IsListening() {
		return nil
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(MacPlistPath); os.IsNotExist(err) {
			return fmt.Errorf("launchd plist not found: %s", MacPlistPath)
		}
		// Try kickstart first in case it's already registered
		if _, err := runElevated("launchctl", "kickstart", "-k", "system/"+MacLabel); err == nil {
			return nil
		}

		out, err := runElevated("launchctl", "bootstrap", "system", MacPlistPath)
		if err != nil {
			// Fallback to load -w for older macOS
			out, err = runElevated("launchctl", "load", "-w", MacPlistPath)
			if err != nil {
				return fmt.Errorf("launchctl error: %w (%s)", err, string(out))
			}
		}
		return nil
	}
	if runtime.GOOS == "linux" {
		if out, err := runElevated("systemctl", "start", "smartnet"); err == nil {
			return nil
		} else {
			_, errLegacy := runElevated("systemctl", "start", "smartdns")
			if errLegacy == nil {
				return nil
			}
			return fmt.Errorf("systemctl error: %s (%w)", string(out), err)
		}
	}
	if runtime.GOOS == "windows" {
		return windowsStart()
	}
	return nil
}

func Stop() error {
	if iface, err := network.ActiveInterface(); err == nil {
		if IsSystemDNSSet(iface) {
			_ = network.ResetDNSServers(iface)
			network.FlushDNSCache()
		}
	}

	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(LegacyMacPlistPath); err == nil {
			_, _ = runElevated("launchctl", "bootout", "system/"+LegacyMacLabel)
			_, _ = runElevated("launchctl", "unload", LegacyMacPlistPath)
		}
		if _, err := os.Stat(MacPlistPath); err == nil {
			_, _ = runElevated("launchctl", "bootout", "system/"+MacLabel)
			_, _ = runElevated("launchctl", "unload", MacPlistPath)
		}
		return nil
	}
	if runtime.GOOS == "linux" {
		_, _ = runElevated("systemctl", "stop", "smartdns")
		_, err := runElevated("systemctl", "stop", "smartnet")
		return err
	}
	if runtime.GOOS == "windows" {
		return windowsStop()
	}
	return nil
}

func Restart() error {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(MacPlistPath); err == nil {
			if _, errKick := runElevated("launchctl", "kickstart", "-k", "system/"+MacLabel); errKick == nil {
				return nil
			}
		} else if _, errOld := os.Stat(LegacyMacPlistPath); os.IsNotExist(errOld) {
			return nil
		}
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(LinuxUnit); err == nil {
			if _, errSys := runElevated("systemctl", "restart", "smartnet"); errSys == nil {
				return nil
			}
		} else if _, errOld := os.Stat(LegacyLinuxUnit); os.IsNotExist(errOld) {
			return nil
		}
	}
	if runtime.GOOS == "windows" {
		return windowsRestart()
	}
	_ = Stop()
	return Start()
}

func Status() (bool, int, error) {
	if runtime.GOOS == "darwin" {
		for _, proc := range []string{"smartnet", "smartdns"} {
			cmdPgrep := exec.Command("pgrep", "-x", proc)
			if out, err := cmdPgrep.Output(); err == nil {
				pidStr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
				if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
					return true, pid, nil
				}
			}
		}

		for _, label := range []string{MacLabel, LegacyMacLabel} {
			cmdPrint := exec.Command("launchctl", "print", "system/"+label)
			if out, err := cmdPrint.Output(); err == nil {
				s := string(out)
				if strings.Contains(s, "state = running") {
					re := regexp.MustCompile(`pid = (\d+)`)
					if m := re.FindStringSubmatch(s); len(m) > 1 {
						pid, _ := strconv.Atoi(m[1])
						return true, pid, nil
					}
					return true, 0, nil
				}
			}
		}

		if IsListening() {
			return true, 0, nil
		}
		return false, 0, nil
	}

	if runtime.GOOS == "linux" {
		for _, unit := range []string{"smartnet", "smartdns"} {
			cmd := exec.Command("systemctl", "is-active", unit)
			out, _ := cmd.Output()
			if strings.TrimSpace(string(out)) == "active" {
				cmdPid := exec.Command("systemctl", "show", "--property", "MainPID", "--value", unit)
				if pOut, err := cmdPid.Output(); err == nil {
					pid, _ := strconv.Atoi(strings.TrimSpace(string(pOut)))
					return true, pid, nil
				}
				return true, 0, nil
			}
		}

		// Fallback: check pgrep if running outside systemd
		for _, proc := range []string{"smartnet", "smartdns"} {
			cmdPgrep := exec.Command("pgrep", "-x", proc)
			if pOut, err := cmdPgrep.Output(); err == nil {
				pidStr := strings.TrimSpace(strings.Split(string(pOut), "\n")[0])
				if p, err := strconv.Atoi(pidStr); err == nil && p > 0 {
					return true, p, nil
				}
			}
		}
		return false, 0, nil
	}

	if runtime.GOOS == "windows" {
		return windowsStatus()
	}

	return false, 0, nil
}

// IsListening checks if port 53 is open on 127.0.0.1 without external tools
func IsListening() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:53", 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return true
	}
	c := new(dns.Client)
	c.Timeout = 250 * time.Millisecond
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	_, _, err = c.Exchange(m, "127.0.0.1:53")
	return err == nil
}

// IsSystemDNSSet checks if 127.0.0.1 is configured as system DNS on active interface
func IsSystemDNSSet(iface string) bool {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("networksetup", "-getdnsservers", iface)
		out, err := cmd.Output()
		if err != nil {
			return false
		}
		return bytes.Contains(out, []byte("127.0.0.1"))
	}
	if runtime.GOOS == "linux" {
		return network.IsLinuxDNSSet(iface)
	}
	if runtime.GOOS == "windows" {
		return network.IsWindowsDNSSet(iface)
	}
	return false
}

func windowsInstall(absBin string) error {
	cmdDel1 := exec.Command("schtasks", "/delete", "/tn", "smartdns", "/f")
	hideWindow(cmdDel1)
	_ = cmdDel1.Run()

	cmdDel2 := exec.Command("schtasks", "/delete", "/tn", "smartnet", "/f")
	hideWindow(cmdDel2)
	_ = cmdDel2.Run()

	taskCmd := fmt.Sprintf(`"%s" daemon`, absBin)
	cmd := exec.Command("schtasks", "/create", "/tn", "smartnet", "/tr", taskCmd, "/sc", "onlogon", "/rl", "highest", "/f")
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create scheduled task: %w (%s)", err, string(out))
	}
	return Start()
}

func windowsUninstall() error {
	_ = Stop()
	cmdDel1 := exec.Command("schtasks", "/delete", "/tn", "smartdns", "/f")
	hideWindow(cmdDel1)
	_ = cmdDel1.Run()

	cmdDel2 := exec.Command("schtasks", "/delete", "/tn", "smartnet", "/f")
	hideWindow(cmdDel2)
	_, err := cmdDel2.CombinedOutput()
	return err
}

func windowsStart() error {
	if IsListening() {
		return nil
	}

	absBin, err := os.Executable()
	if err != nil {
		absBin = "smartnet.exe"
	}
	logPath := config.GetLogPath()
	_ = os.MkdirAll(filepath.Dir(logPath), 0755)

	// Launch headless background daemon directly with CREATE_NO_WINDOW
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	cmdDaemon := exec.Command(absBin, "daemon")
	hideWindow(cmdDaemon)
	if err == nil {
		cmdDaemon.Stdout = logFile
		cmdDaemon.Stderr = logFile
	}
	if errStart := cmdDaemon.Start(); errStart == nil {
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
			if IsListening() {
				return nil
			}
		}
	}

	// Fallback to schtasks if direct exec didn't bind port
	cmdSch := exec.Command("schtasks", "/run", "/tn", "smartnet")
	hideWindow(cmdSch)
	if err := cmdSch.Run(); err == nil {
		for i := 0; i < 20; i++ {
			time.Sleep(100 * time.Millisecond)
			if IsListening() {
				return nil
			}
		}
	}

	return nil
}

func windowsStop() error {
	currentPID := os.Getpid()
	cmdSch1 := exec.Command("schtasks", "/end", "/tn", "smartnet")
	hideWindow(cmdSch1)
	_ = cmdSch1.Run()

	cmdSch2 := exec.Command("schtasks", "/end", "/tn", "smartdns")
	hideWindow(cmdSch2)
	_ = cmdSch2.Run()

	// Terminate background processes excluding the current CLI process
	psCmd := fmt.Sprintf(`Get-Process -Name smartnet,smartdns -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne %d } | Stop-Process -Force -ErrorAction SilentlyContinue`, currentPID)
	cmdPS := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	hideWindow(cmdPS)
	_ = cmdPS.Run()
	return nil
}

func windowsRestart() error {
	_ = Stop()
	time.Sleep(500 * time.Millisecond)
	return Start()
}

func windowsStatus() (bool, int, error) {
	currentPID := os.Getpid()
	for _, exe := range []string{"smartnet.exe", "smartdns.exe"} {
		cmd := exec.Command("tasklist", "/fi", fmt.Sprintf("imagename eq %s", exe), "/fo", "csv", "/nh")
		hideWindow(cmd)
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, line := range lines {
				fields := strings.Split(line, ",")
				if len(fields) >= 2 {
					name := strings.Trim(fields[0], "\" ")
					if strings.EqualFold(name, exe) {
						pidStr := strings.Trim(fields[1], "\" ")
						if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
							// Filter out the current CLI command process!
							if pid == currentPID {
								continue
							}
							return true, pid, nil
						}
					}
				}
			}
		}
	}
	if IsListening() {
		return true, 0, nil
	}
	return false, 0, nil
}

