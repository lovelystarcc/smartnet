package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"smartnet/pkg/completion"
	"smartnet/pkg/config"
	"smartnet/pkg/fakeip"
	"smartnet/pkg/network"
	"smartnet/pkg/proxy"
	"smartnet/pkg/resolver"
	"smartnet/pkg/rules"
	"smartnet/pkg/service"
	"smartnet/pkg/tester"
	"smartnet/pkg/tun"
	"smartnet/pkg/vless"

	"github.com/miekg/dns"
)

const Version = "2.0.9"

func printHelp() {
	fmt.Printf(`%sSmartNet CLI v%s%s — DNS, VLESS-Reality VPN & Transparent TUN Proxy

%sUSAGE:%s
  smartnet <command> [arguments...]

%sCORE COMMANDS:%s
  %son%s [profile] [--vpn] Enable DNS on the active network interface (with optional 1-click VPN)
  %soff%s              Disable DNS (revert to DHCP) and stop any active VPN/TUN
  %stoggle%s           Toggle DNS state (enable / disable)
  %sstatus%s           Show status (DNS, VPN, TUN, Egress IP)
  %stest%s [domains...] Test latency, TLS ping, and routing to domains
  %supdate%s           Update SmartNet to latest version from GitHub
  %scompletion%s <sh>  Generate shell completion script (fish, zsh, bash, powershell)

%sVPN & ANTI-CENSORSHIP TUNNEL (VLESS-REALITY):%s
  %svpn%s [on|off|toggle|status] Fake-IP TUN Proxy (enables VLESS, TUN adapter & Fake-IP)
  %svpn%s set <vless://...>    Configure VLESS Reality server URI for active profile

%sADVANCED ADAPTER & ENGINE CONTROLS:%s
  %stun%s [on|off|status]      Granular Virtual TUN adapter control (tun2socks transparent mode)
  %sfakeip%s [on|off|status|clear] Granular Fake-IP engine control (198.18.0.0/15)
  %sbypass%s [add|remove|list]   Manage direct resolution whitelist

%sDEVELOPER TOOLS & PROXY BRIDGE:%s
  %srun%s [--] <cmd...> Run command with proxy environment injected (curl, git, brew)
  %senv%s [sh]         Output shell export commands for proxy (use with eval or iex)
  %sproxy%s status|run Manage local Mixed HTTP/SOCKS5 proxy bridge (127.0.0.1:7890)

%sPROFILE MANAGEMENT:%s
  %slist%s             List all configured profiles
  %suse%s <name>        Switch active profile
  %sadd%s <name> <url> [backup]  Add a new profile (with optional secondary upstream)
  %sremove%s <name>     Remove a profile

%sSETUP:%s
  %ssetup%s <url> [name] Configure service, profile, and network interface

%sSYSTEM DAEMON:%s
  %sservice%s install  Install background service into startup
  %sservice%s start|stop|restart|status|uninstall
  %sdaemon%s           Run DNS server, proxy bridge, and TUN adapter in foreground
  %slog%s [-f|-n|-c]   Show or follow daemon log output

%sEXAMPLES:%s
  smartnet setup https://dns.example.com/dns-query personal
  smartnet vpn set vless://uuid@server:443?security=reality&sni=dl.google.com&pbk=key&sid=id
  smartnet vpn on       # 1-Click: enables VLESS + TUN + Fake-IP + DNS
  smartnet status
  smartnet vpn off      # Disables VPN & TUN (keeps SmartDNS)
  smartnet off          # Full disable
`,
		tester.Bold, Version, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Green, tester.Reset,
		tester.Yellow, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Green, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Green, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Green, tester.Reset,
		tester.Bold, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Cyan, tester.Reset,
		tester.Bold, tester.Reset,
	)
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	cmd := strings.ToLower(os.Args[1])

	switch cmd {
	case "version", "-v", "--version":
		fmt.Printf("smartnet version %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)

	case "help", "-h", "--help":
		printHelp()

	case "on":
		handleOn()

	case "off":
		handleOff()

	case "toggle":
		handleToggle()

	case "status":
		handleStatus()

	case "dns":
		handleDNS()

	case "vpn":
		handleVPN()

	case "test":
		handleTest()

	case "list", "ls":
		handleList()

	case "use":
		handleUse()

	case "add":
		handleAdd()

	case "remove", "rm", "delete":
		handleRemove()

	case "setup", "init":
		handleSetup()

	case "service":
		handleService()

	case "daemon":
		handleDaemon()

	case "log", "logs":
		handleLog()

	case "proxy":
		handleProxy()

	case "run":
		handleRun()

	case "env":
		handleEnv()

	case "update", "upgrade":
		handleUpdate()

	case "fakeip", "fake-ip":
		handleFakeIP()

	case "bypass", "split":
		handleBypass()

	case "tun":
		handleTUN()

	case "completion":
		handleCompletion()

	default:
		fmt.Printf("%sUnknown command: %s%s\n\n", tester.Red, cmd, tester.Reset)
		printHelp()
		os.Exit(1)
	}
}

// ensureServiceReadyAndSetDNS verifies that the background service is running and
// listening on 127.0.0.1:53 before setting system DNS. If the daemon fails to listen,
// it ensures system DNS is reverted to DHCP and returns an error.
func ensureServiceReadyAndSetDNS(iface string) error {
	if !service.IsListening() {
		running, _, _ := service.Status()
		if running {
			_ = service.Restart()
		} else {
			_ = service.Start()
		}

		ready := false
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
			if service.IsListening() {
				ready = true
				break
			}
		}

		if !ready {
			_ = network.ResetDNSServers(iface)
			return fmt.Errorf("SmartNet daemon failed to bind port 53 or is not responding; DNS was reverted")
		}
	}

	if err := network.SetDNSServers(iface, "127.0.0.1"); err != nil {
		_ = network.ResetDNSServers(iface)
		return fmt.Errorf("failed to configure system DNS on %s: %w", iface, err)
	}
	network.FlushDNSCache()
	return nil
}

func handleOn() {
	handleOnWithArgs(os.Args[2:])
}

func handleOnWithArgs(args []string) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sFailed to load config: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	withVPN := false
	profileChanged := false
	for _, arg := range args {
		if arg == "--vpn" || arg == "-v" {
			withVPN = true
		} else if !strings.HasPrefix(arg, "-") && arg != "on" && arg != "toggle" && arg != "dns" {
			targetProfile := arg
			if err := cfg.SetActive(targetProfile); err != nil {
				fmt.Printf("%s%v%s\n", tester.Red, err, tester.Reset)
				os.Exit(1)
			}
			profileChanged = true
		}
	}
	if profileChanged {
		_ = cfg.Save()
		_ = service.Restart()
	}

	iface, err := network.ActiveInterface()
	if err != nil {
		iface = "Wi-Fi"
	}

	active := cfg.GetActive()
	if active == nil {
		fmt.Printf("%sNo DNS profiles configured.%s\nAdd a server:\n  smartnet setup <url> [name]\n  smartnet add <name> <url>\n", tester.Yellow, tester.Reset)
		os.Exit(1)
	}
	_ = network.EnsureRouteBypass(active.Upstream)

	if withVPN {
		if active.VLESS != nil {
			active.VPN = true
			active.TUN = true
			active.FakeIP = true
			_ = cfg.Save()
			_ = service.Restart()
		} else {
			fmt.Printf("%sNo VLESS configuration found for profile '%s'. Skipping VPN activation.%s\n", tester.Yellow, active.Name, tester.Reset)
		}
	}

	if err := ensureServiceReadyAndSetDNS(iface); err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		fmt.Printf("Safety Watchdog: System DNS was not modified or was reverted.\n")
		fmt.Printf("Run '%ssmartnet log%s' to inspect daemon startup logs, or run '%ssmartnet daemon%s' in a console.\n", tester.Bold, tester.Reset, tester.Bold, tester.Reset)
		os.Exit(1)
	}

	profileName := cfg.ActiveProfile
	vpnSuffix := ""
	if active.VPN {
		vpnSuffix = fmt.Sprintf(" %s[VPN: Active]%s", tester.Green, tester.Reset)
	}
	fmt.Printf("%sDNS enabled (127.0.0.1)%s on interface %s%s%s [Profile: %s%s%s]%s\n",
		tester.Green, tester.Reset,
		tester.Bold, iface, tester.Reset,
		tester.Cyan, profileName, tester.Reset,
		vpnSuffix,
	)
}

func handleOff() {
	iface, err := network.ActiveInterface()
	if err != nil {
		iface = "Wi-Fi"
	}

	if err := network.ResetDNSServers(iface); err != nil {
		fmt.Printf("%sFailed to disable DNS: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	// Also disable TUN, Fake-IP and VPN if active so traffic does not get lost
	cfg, err := config.Load()
	if err == nil {
		active := cfg.GetActive()
		if active != nil && (active.VPN || active.TUN || active.FakeIP) {
			active.VPN = false
			active.TUN = false
			active.FakeIP = false
			fakeip.DefaultPool.Clear()
			_ = cfg.Save()
			_ = service.Restart()
		}
	}
	network.FlushDNSCache()

	fmt.Printf("%sDNS disabled (DHCP)%s on interface %s%s%s\n",
		tester.Dim, tester.Reset,
		tester.Bold, iface, tester.Reset,
	)
}

func handleToggle() {
	handleToggleWithArgs(os.Args[2:])
}

func handleToggleWithArgs(args []string) {
	iface, err := network.ActiveInterface()
	if err != nil {
		iface = "Wi-Fi"
	}

	if service.IsSystemDNSSet(iface) {
		handleOff()
	} else {
		handleOnWithArgs(args)
	}
}

func handleStatus() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sFailed to load config: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	fmt.Printf("\n%sSmartNet Status%s\n", tester.Bold, tester.Reset)
	fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)

	// 1. Daemon service status
	running, pid, _ := service.Status()
	listening := service.IsListening()
	serviceStr := ""
	if running {
		if listening {
			serviceStr = fmt.Sprintf("%s● Running%s (PID: %d, port 53 active)", tester.Green, tester.Reset, pid)
		} else {
			serviceStr = fmt.Sprintf("%s● Warning: Process alive (PID: %d), but port 53 is NOT responding!%s", tester.Yellow, pid, tester.Reset)
		}
	} else {
		// Check if something else is listening on 53
		if listening {
			serviceStr = fmt.Sprintf("%s● Active%s (port 53 in use by another service)", tester.Yellow, tester.Reset)
		} else {
			serviceStr = fmt.Sprintf("%s● Stopped%s", tester.Red, tester.Reset)
		}
	}
	fmt.Printf(" Resolver service (127.0.0.1:53) : %s\n", serviceStr)

	// 2. Proxy bridge status
	proxyAddr := cfg.ProxyAddr
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:7890"
	}
	proxyStr := ""
	if proxy.IsListening(proxyAddr) {
		proxyStr = fmt.Sprintf("%s● Active%s (%s, Mixed HTTP/SOCKS5)", tester.Green, tester.Reset, proxyAddr)
	} else {
		proxyStr = fmt.Sprintf("%s● Stopped%s (%s)", tester.Yellow, tester.Reset, proxyAddr)
	}
	fmt.Printf(" Proxy bridge (%-17s) : %s\n", proxyAddr, proxyStr)

	// 3. Active network interface & DNS
	iface, _ := network.ActiveInterface()
	servers, _ := network.GetDNSServers(iface)
	dnsSet := service.IsSystemDNSSet(iface)

	statusStr := ""
	if dnsSet {
		statusStr = fmt.Sprintf("%s● Enabled%s (127.0.0.1)", tester.Green, tester.Reset)
	} else {
		statusStr = fmt.Sprintf("%s● Disabled%s (%s)", tester.Yellow, tester.Reset, strings.Join(servers, ", "))
	}
	fmt.Printf(" System DNS (%-20s) : %s\n", iface, statusStr)

	// 4. Active Profile
	active := cfg.GetActive()
	if active != nil {
		fmt.Printf(" Active profile                  : %s%s%s\n", tester.Cyan, active.Name, tester.Reset)
		fmt.Printf(" Primary DoH URL                 : %s\n", active.Upstream)
		if active.BackupUpstream != "" {
			fmt.Printf(" Secondary (Backup) DoH          : %s%s%s\n", tester.Yellow, active.BackupUpstream, tester.Reset)
		}
		if active.ProxyUpstream != "" {
			fmt.Printf(" Proxy Upstream                  : %s%s%s\n", tester.Cyan, active.ProxyUpstream, tester.Reset)
		}
		if active.Desc != "" {
			fmt.Printf(" Description                     : %s%s%s\n", tester.Dim, active.Desc, tester.Reset)
		}
	} else {
		fmt.Printf(" Active profile                  : %sNot configured%s (run: smartnet setup <url>)\n", tester.Yellow, tester.Reset)
	}

	// 5. Split DNS Engine
	bypassSummary := ".ru, .рф, .su, domestic services, LAN"
	if active != nil && len(active.BypassDomains) > 0 {
		bypassSummary += fmt.Sprintf(" (+%d custom)", len(active.BypassDomains))
	}
	fmt.Printf(" Split DNS Engine                : %s● Active%s (Direct bypass: %s)\n", tester.Green, tester.Reset, bypassSummary)

	// 6. Fake-IP Engine
	fakeIPStr := fmt.Sprintf("%s● Inactive%s (enable with 'smartnet fakeip on')", tester.Yellow, tester.Reset)
	if active != nil && active.FakeIP {
		alloc, _, err := fakeip.QueryDaemonStats(cfg.ProxyAddr)
		if err != nil {
			alloc, _ = fakeip.DefaultPool.Stats()
		}
		fakeIPStr = fmt.Sprintf("%s● Active%s (%d IPs allocated in 198.18.0.0/15)", tester.Green, tester.Reset, alloc)
	}
	fmt.Printf(" Fake-IP Engine (198.18.0.0/15)  : %s\n", fakeIPStr)

	// 7. Virtual TUN Adapter
	tunStr := fmt.Sprintf("%s● Inactive%s (enable with 'smartnet tun on')", tester.Yellow, tester.Reset)
	if active != nil && active.TUN {
		tunStr = fmt.Sprintf("%s● Active%s (198.18.0.0/15 -> userspace netstack)", tester.Green, tester.Reset)
	}
	fmt.Printf(" Virtual TUN Adapter             : %s\n", tunStr)

	// 8. VPN Tunnel (VLESS-Reality)
	vpnStr := fmt.Sprintf("%s● Inactive%s (enable with 'smartnet vpn on')", tester.Yellow, tester.Reset)
	if active != nil && active.VPN {
		serverName := "configured"
		if active.VLESS != nil {
			serverName = fmt.Sprintf("%s:%d (SNI: %s)", active.VLESS.Server, active.VLESS.Port, active.VLESS.ServerName)
		}
		vpnStr = fmt.Sprintf("%s● Active%s (%s)", tester.Green, tester.Reset, serverName)
	} else if active != nil && active.VLESS != nil {
		vpnStr = fmt.Sprintf("%s● Ready%s (server: %s:%d, toggle with 'smartnet vpn on')", tester.Cyan, tester.Reset, active.VLESS.Server, active.VLESS.Port)
	}
	fmt.Printf(" VPN Tunnel (VLESS-Reality)      : %s\n", vpnStr)

	// 9. Auto-Fallback Protection
	gw := network.GetPhysicalGateway()
	fallbacks := []string{"1.1.1.1", "8.8.8.8", "77.88.8.8"}
	if gw != "" {
		fallbacks = append([]string{gw + " (Gateway)"}, fallbacks...)
	}
	fmt.Printf(" Auto-Fallback Protection        : %s● Active%s (%s)\n", tester.Green, tester.Reset, strings.Join(fallbacks, ", "))

	// 10. Public Egress IP
	if pubIP, err := network.GetPublicIP(); err == nil && pubIP != nil {
		fmt.Printf(" Public Egress IP                : %s● %s%s\n", tester.Cyan, pubIP.String(), tester.Reset)
	}

	fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
	fmt.Printf(" Total profiles: %d (use %ssmartnet list%s)\n\n", len(cfg.Profiles), tester.Cyan, tester.Reset)
}

func handleTest() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sConfig error: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	active := cfg.GetActive()
	vpsIP := ""
	if active != nil {
		if u, err := url.Parse(active.Upstream); err == nil {
			vpsIP = u.Hostname()
		}
	}

	domains := os.Args[2:]

	fmt.Printf("\n%sTesting connection via SmartNet%s\n", tester.Bold, tester.Reset)
	fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────────────────" + tester.Reset)

	iface, _ := network.ActiveInterface()
	dnsSet := service.IsSystemDNSSet(iface)
	sysStatus := fmt.Sprintf("%s● Disabled%s", tester.Yellow, tester.Reset)
	if dnsSet {
		sysStatus = fmt.Sprintf("%s● Enabled%s (127.0.0.1)", tester.Green, tester.Reset)
	}

	resStatus := fmt.Sprintf("%s● Not responding%s", tester.Red, tester.Reset)
	if service.IsListening() {
		resStatus = fmt.Sprintf("%s● Active%s (profile: %s%s%s)", tester.Green, tester.Reset, tester.Cyan, cfg.ActiveProfile, tester.Reset)
	}

	pubIP, _ := network.GetPublicIP()
	egressStr := fmt.Sprintf("%sDetecting...%s", tester.Dim, tester.Reset)
	if pubIP != nil {
		egressStr = fmt.Sprintf("%s● %s%s", tester.Cyan, pubIP.String(), tester.Reset)
	}

	fmt.Printf(" Local resolver (127.0.0.1:53) : %s\n", resStatus)
	fmt.Printf(" System DNS (%-18s) : %s\n", iface, sysStatus)
	fmt.Printf(" Public Egress IP              : %s\n", egressStr)
	fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────────────────" + tester.Reset)
	fmt.Println()

	tester.Run(domains, vpsIP)
}

func handleList() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if len(cfg.Profiles) == 0 {
		fmt.Printf("\n%sDNS profile list is empty.%s\nAdd a server:\n  smartnet setup <url> [name]\n  smartnet add <name> <url>\n\n", tester.Yellow, tester.Reset)
		return
	}

	fmt.Printf("\n%sDNS Profile List:%s\n", tester.Bold, tester.Reset)
	fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)

	for name, p := range cfg.Profiles {
		indicator := "  "
		nameColor := tester.Reset
		if name == cfg.ActiveProfile {
			indicator = tester.Green + "● " + tester.Reset
			nameColor = tester.Bold + tester.Green
		}
		fmt.Printf("%s%-14s %s\n", indicator, nameColor+name+tester.Reset, p.Upstream)
		if p.BackupUpstream != "" {
			fmt.Printf("    %sBackup:   %s%s\n", tester.Dim, p.BackupUpstream, tester.Reset)
		}
		if p.Desc != "" {
			fmt.Printf("    %s%s%s\n", tester.Dim, p.Desc, tester.Reset)
		}
	}
	fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
	fmt.Printf("Switch profile: %ssmartnet use <name>%s\n\n", tester.Cyan, tester.Reset)
}

func handleUse() {
	if len(os.Args) < 3 {
		fmt.Printf("%sUsage: smartnet use <profile_name>%s\n", tester.Yellow, tester.Reset)
		os.Exit(1)
	}
	name := os.Args[2]

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if err := cfg.SetActive(name); err != nil {
		fmt.Printf("%s%v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if err := cfg.Save(); err != nil {
		fmt.Printf("%sFailed to save config: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	_ = service.Restart()
	fmt.Printf("%sActive profile switched to '%s'%s (%s)\n",
		tester.Green, name, tester.Reset, cfg.GetActive().Upstream)
}

func handleAdd() {
	if len(os.Args) < 4 {
		fmt.Printf(`%sUsage: smartnet add <name> <upstream_url> [backup_url] [description]%s

Examples:
  smartnet add personal https://dns.example.com/dns-query
  smartnet add personal https://dns.example.com/dns-query https://1.1.1.1/dns-query "With Cloudflare backup"
`, tester.Yellow, tester.Reset)
		os.Exit(1)
	}

	name := os.Args[2]
	upstream := os.Args[3]
	backup := ""
	desc := ""

	if len(os.Args) > 4 {
		arg4 := os.Args[4]
		if strings.HasPrefix(arg4, "http://") || strings.HasPrefix(arg4, "https://") {
			backup = arg4
			if len(os.Args) > 5 {
				desc = strings.Join(os.Args[5:], " ")
			}
		} else {
			desc = strings.Join(os.Args[4:], " ")
		}
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	p := &config.Profile{
		Name:           name,
		Upstream:       upstream,
		BackupUpstream: backup,
		Desc:           desc,
	}

	if err := cfg.AddProfile(p); err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if err := cfg.Save(); err != nil {
		fmt.Printf("%sFailed to save config: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	fmt.Printf("%sProfile '%s' added successfully!%s\n", tester.Green, name, tester.Reset)
}

func handleRemove() {
	if len(os.Args) < 3 {
		fmt.Printf("%sUsage: smartnet remove <name>%s\n", tester.Yellow, tester.Reset)
		os.Exit(1)
	}
	name := os.Args[2]

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if err := cfg.RemoveProfile(name); err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if err := cfg.Save(); err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	fmt.Printf("%sProfile '%s' removed.%s\n", tester.Green, name, tester.Reset)
}

func handleSetup() {
	if len(os.Args) < 3 {
		fmt.Printf(`%sUsage: smartnet setup <upstream_url> [profile_name]%s

Example:
  sudo smartnet setup https://dns.example.com/dns-query personal
`, tester.Yellow, tester.Reset)
		os.Exit(1)
	}

	upstream := os.Args[2]
	profileName := "personal"
	if len(os.Args) > 3 {
		profileName = os.Args[3]
	}

	fmt.Printf("\n%sQuick setup for SmartNet...%s\n", tester.Bold, tester.Reset)

	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	_ = cfg.AddProfile(&config.Profile{
		Name:     profileName,
		Upstream: upstream,
		Desc:     "Custom DNS server",
	})
	_ = cfg.SetActive(profileName)
	_ = cfg.Save()
	fmt.Printf(" [1/4] Profile '%s' configured (%s)\n", profileName, upstream)

	// Install service
	binPath, err := os.Executable()
	if err != nil {
		binPath = "smartnet"
	}
	if err := service.Install(binPath); err != nil {
		fmt.Printf("%s [!] Service warning: %v%s\n", tester.Yellow, err, tester.Reset)
	} else {
		fmt.Println(" [2/4] System service installed and started")
	}

	// Turn on DNS only after verifying daemon is listening
	iface, err := network.ActiveInterface()
	if err != nil {
		iface = "Wi-Fi"
	}
	_ = network.EnsureRouteBypass(upstream)
	if err := ensureServiceReadyAndSetDNS(iface); err != nil {
		fmt.Printf("%s [!] Failed to activate DNS: %v%s\n", tester.Red, err, tester.Reset)
		fmt.Printf(" Service did not become ready. System DNS was not modified.\n")
		fmt.Printf(" Run '%ssmartnet daemon%s' to diagnose startup errors.\n", tester.Bold, tester.Reset)
	} else {
		fmt.Printf(" [3/4] DNS verified and enabled on interface %s (127.0.0.1)\n", iface)
	}

	time.Sleep(500 * time.Millisecond)

	// Quick test
	fmt.Printf(" [4/4] Verifying connectivity...\n")
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err == nil && r != nil && len(r.Answer) > 0 {
		fmt.Printf("\n%sSetup completed successfully. SmartNet is active and running.%s\n\n", tester.Bold+tester.Green, tester.Reset)
	} else {
		fmt.Printf("\n%sSetup completed, but the test query did not respond immediately.%s\n\n", tester.Yellow, tester.Reset)
	}
}

func handleService() {
	if len(os.Args) < 3 {
		fmt.Printf("%sUsage: smartnet service <install|uninstall|start|stop|restart|status>%s\n", tester.Yellow, tester.Reset)
		os.Exit(1)
	}

	action := strings.ToLower(os.Args[2])
	binPath, err := os.Executable()
	if err != nil {
		binPath = "smartnet"
	}

	switch action {
	case "install":
		if err := service.Install(binPath); err != nil {
			fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		fmt.Printf("%sService successfully installed and started!%s\n", tester.Green, tester.Reset)

	case "uninstall":
		if err := service.Uninstall(); err != nil {
			fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		fmt.Printf("%sService removed from system.%s\n", tester.Green, tester.Reset)

	case "start":
		if err := service.Start(); err != nil {
			fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		fmt.Printf("%sService started.%s\n", tester.Green, tester.Reset)

	case "stop":
		if err := service.Stop(); err != nil {
			fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		fmt.Printf("%sService stopped.%s\n", tester.Green, tester.Reset)

	case "restart":
		if err := service.Restart(); err != nil {
			fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		fmt.Printf("%sService restarted.%s\n", tester.Green, tester.Reset)

	case "status":
		running, pid, _ := service.Status()
		if running {
			fmt.Printf("%s● Service running%s (PID: %d)\n", tester.Green, tester.Reset, pid)
		} else {
			fmt.Printf("%s● Service stopped%s\n", tester.Red, tester.Reset)
		}
	}
}

func handleDaemon() {
	// Configure daemon logging to both file and stderr
	logPath := config.GetLogPath()
	_ = os.MkdirAll(filepath.Dir(logPath), 0755)
	if logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		defer logFile.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, logFile))
	}

	// Emergency watchdog on panic: revert DNS to DHCP if port 53 was broken
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[smartnet] FATAL CRASH: %v\n%s", r, debug.Stack())
			iface, errNet := network.ActiveInterface()
			if errNet == nil && service.IsSystemDNSSet(iface) {
				log.Printf("[smartnet] Emergency Watchdog: Reverting DNS on %s to DHCP", iface)
				_ = network.ResetDNSServers(iface)
			}
		}
	}()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	active := cfg.GetActive()
	if active == nil {
		log.Fatalf("No active DNS profile configured")
	}

	log.Printf("[smartnet] Starting server (profile: %s, upstream: %s)", active.Name, active.Upstream)

	var tunStack *tun.Stack
	if active.TUN {
		ts, err := tun.NewStack(cfg)
		if err != nil {
			log.Printf("[smartnet] Error: Failed to create TUN adapter: %v. Disabling Fake-IP to prevent traffic blackholing.", err)
			active.FakeIP = false
			active.TUN = false
		} else if err := ts.Start(); err != nil {
			log.Printf("[smartnet] Error: Failed to start TUN stack: %v. Disabling Fake-IP to prevent traffic blackholing.", err)
			active.FakeIP = false
			active.TUN = false
		} else {
			tunStack = ts
			log.Printf("[smartnet] TUN adapter '%s' active (198.18.0.0/15 -> userspace netstack)", tunStack.DeviceName())
		}
	} else if active.FakeIP {
		log.Printf("[smartnet] Warning: FakeIP is enabled without TUN adapter; disabling FakeIP to prevent traffic blackholing.")
		active.FakeIP = false
	}

	srv := resolver.New(cfg)
	if err := srv.Start(); err != nil {
		if tunStack != nil {
			tunStack.Stop()
		}
		log.Printf("[smartnet] Failed to start DNS server: %v", err)
		iface, errNet := network.ActiveInterface()
		if errNet == nil && service.IsSystemDNSSet(iface) {
			log.Printf("[smartnet] Emergency Watchdog: Reverting DNS on %s to DHCP due to port 53 bind failure", iface)
			_ = network.ResetDNSServers(iface)
		}
		log.Fatalf("Aborting daemon due to startup failure: %v", err)
	}

	proxySrv := proxy.New(cfg)
	if err := proxySrv.Start(); err != nil {
		log.Printf("[smartnet] Warning: Failed to start proxy bridge: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			log.Println("[smartnet] Received SIGHUP, reloading configuration...")
			newCfg, err := config.Load()
			if err == nil {
				cfg = newCfg
				srv.Stop()
				proxySrv.Stop()
				if tunStack != nil {
					tunStack.Stop()
					tunStack = nil
				}

				newActive := cfg.GetActive()
				if newActive != nil && newActive.TUN {
					ts, err := tun.NewStack(cfg)
					if err != nil {
						log.Printf("[smartnet] Error: Failed to create TUN adapter on reload: %v. Disabling Fake-IP to prevent traffic blackholing.", err)
						newActive.FakeIP = false
						newActive.TUN = false
					} else if err := ts.Start(); err != nil {
						log.Printf("[smartnet] Error: Failed to start TUN stack on reload: %v. Disabling Fake-IP to prevent traffic blackholing.", err)
						newActive.FakeIP = false
						newActive.TUN = false
					} else {
						tunStack = ts
						log.Printf("[smartnet] TUN adapter '%s' reloaded", tunStack.DeviceName())
					}
				} else if newActive != nil && newActive.FakeIP {
					newActive.FakeIP = false
				}

				srv = resolver.New(cfg)
				proxySrv = proxy.New(cfg)
				_ = srv.Start()
				_ = proxySrv.Start()
			}
			continue
		}
		log.Println("[smartnet] Shutting down...")
		if tunStack != nil {
			tunStack.Stop()
		}
		srv.Stop()
		proxySrv.Stop()
		break
	}
}

func handleLog() {
	logPath := config.GetLogPath()
	args := os.Args[2:]

	follow := false
	clear := false
	linesCount := 50

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--follow":
			follow = true
		case "-c", "--clear":
			clear = true
		case "-n", "--lines":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					linesCount = n
					i++
				}
			}
		}
	}

	if clear {
		if err := os.Truncate(logPath, 0); err != nil {
			fmt.Printf("%sFailed to clear log file %s: %v%s\n", tester.Red, logPath, err, tester.Reset)
			os.Exit(1)
		}
		fmt.Printf("%sLog file cleared: %s%s\n", tester.Green, logPath, tester.Reset)
		return
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%sLog file not found at %s. No logs recorded yet.%s\n", tester.Yellow, logPath, tester.Reset)
			return
		}
		fmt.Printf("%sFailed to read log file %s: %v%s\n", tester.Red, logPath, err, tester.Reset)
		os.Exit(1)
	}

	content := strings.TrimSpace(string(data))
	if content != "" {
		lines := strings.Split(content, "\n")
		start := 0
		if len(lines) > linesCount {
			start = len(lines) - linesCount
		}
		fmt.Println(strings.Join(lines[start:], "\n"))
	} else {
		fmt.Printf("%sLog file is currently empty (%s).%s\n", tester.Dim, logPath, tester.Reset)
	}

	if follow {
		f, err := os.Open(logPath)
		if err != nil {
			return
		}
		defer f.Close()
		_, _ = f.Seek(0, io.SeekEnd)
		reader := bufio.NewReader(f)
		for {
			line, err := reader.ReadString('\n')
			if err == nil {
				fmt.Print(line)
			} else {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
}

func handleRun() {
	if len(os.Args) < 3 {
		fmt.Printf(`%sUsage: smartnet run [--] <command> [args...]%s

Examples:
  smartnet run -- git clone https://github.com/...
  smartnet run -- curl -I https://blocked-site.com
  smartnet run brew update
`, tester.Yellow, tester.Reset)
		os.Exit(1)
	}

	args := os.Args[2:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Printf("%sNo command specified to run%s\n", tester.Red, tester.Reset)
		os.Exit(1)
	}

	cfg, _ := config.Load()
	proxyAddr := "127.0.0.1:7890"
	if cfg != nil && cfg.ProxyAddr != "" {
		proxyAddr = cfg.ProxyAddr
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	env = append(env,
		fmt.Sprintf("HTTP_PROXY=http://%s", proxyAddr),
		fmt.Sprintf("HTTPS_PROXY=http://%s", proxyAddr),
		fmt.Sprintf("ALL_PROXY=socks5://%s", proxyAddr),
		fmt.Sprintf("http_proxy=http://%s", proxyAddr),
		fmt.Sprintf("https_proxy=http://%s", proxyAddr),
		fmt.Sprintf("all_proxy=socks5://%s", proxyAddr),
	)
	cmd.Env = env

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Printf("%sCommand failed: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}
}

func handleEnv() {
	cfg, _ := config.Load()
	proxyAddr := "127.0.0.1:7890"
	if cfg != nil && cfg.ProxyAddr != "" {
		proxyAddr = cfg.ProxyAddr
	}
	httpURL := "http://" + proxyAddr
	socksURL := "socks5://" + proxyAddr

	isUnset := false
	sh := ""
	for _, arg := range os.Args[2:] {
		if arg == "-u" || arg == "--unset" {
			isUnset = true
		} else if !strings.HasPrefix(arg, "-") {
			sh = strings.ToLower(arg)
		}
	}

	if sh == "" {
		if runtime.GOOS == "windows" {
			sh = "powershell"
		} else {
			shellEnv := os.Getenv("SHELL")
			if strings.Contains(shellEnv, "fish") {
				sh = "fish"
			} else {
				sh = "zsh"
			}
		}
	}

	if isUnset {
		if sh == "fish" {
			fmt.Println("set -e HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy")
		} else if sh == "powershell" || sh == "pwsh" {
			fmt.Println("Remove-Item env:HTTP_PROXY, env:HTTPS_PROXY, env:ALL_PROXY, env:http_proxy, env:https_proxy, env:all_proxy -ErrorAction SilentlyContinue")
		} else {
			fmt.Println("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy")
		}
		return
	}

	if sh == "fish" {
		fmt.Printf("set -gx HTTP_PROXY %s\n", httpURL)
		fmt.Printf("set -gx HTTPS_PROXY %s\n", httpURL)
		fmt.Printf("set -gx ALL_PROXY %s\n", socksURL)
		fmt.Printf("set -gx http_proxy %s\n", httpURL)
		fmt.Printf("set -gx https_proxy %s\n", httpURL)
		fmt.Printf("set -gx all_proxy %s\n", socksURL)
	} else if sh == "powershell" || sh == "pwsh" {
		fmt.Printf("$env:HTTP_PROXY = \"%s\"\n", httpURL)
		fmt.Printf("$env:HTTPS_PROXY = \"%s\"\n", httpURL)
		fmt.Printf("$env:ALL_PROXY = \"%s\"\n", socksURL)
		fmt.Printf("$env:http_proxy = \"%s\"\n", httpURL)
		fmt.Printf("$env:https_proxy = \"%s\"\n", httpURL)
		fmt.Printf("$env:all_proxy = \"%s\"\n", socksURL)
	} else {
		fmt.Printf("export HTTP_PROXY=\"%s\"\n", httpURL)
		fmt.Printf("export HTTPS_PROXY=\"%s\"\n", httpURL)
		fmt.Printf("export ALL_PROXY=\"%s\"\n", socksURL)
		fmt.Printf("export http_proxy=\"%s\"\n", httpURL)
		fmt.Printf("export https_proxy=\"%s\"\n", httpURL)
		fmt.Printf("export all_proxy=\"%s\"\n", socksURL)
	}
}

func handleProxy() {
	cfg, _ := config.Load()
	proxyAddr := "127.0.0.1:7890"
	if cfg != nil && cfg.ProxyAddr != "" {
		proxyAddr = cfg.ProxyAddr
	}

	if len(os.Args) < 3 {
		active := proxy.IsListening(proxyAddr)
		statusStr := fmt.Sprintf("%s● Inactive%s", tester.Yellow, tester.Reset)
		if active {
			statusStr = fmt.Sprintf("%s● Active%s", tester.Green, tester.Reset)
		}
		fmt.Printf("\n%sSmartNet Proxy Bridge%s\n", tester.Bold, tester.Reset)
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf(" Local listener  : %s (%s, Mixed HTTP/SOCKS5)\n", proxyAddr, statusStr)
		if cfg != nil && cfg.GetActive() != nil && cfg.GetActive().ProxyUpstream != "" {
			fmt.Printf(" Proxy upstream  : %s\n", cfg.GetActive().ProxyUpstream)
		} else {
			fmt.Printf(" Proxy upstream  : Direct dial via SmartNet\n")
		}
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf("Usage:\n  smartnet proxy status\n  smartnet proxy run\n  smartnet proxy set <upstream_url>\n\n")
		return
	}

	action := strings.ToLower(os.Args[2])
	switch action {
	case "status":
		if proxy.IsListening(proxyAddr) {
			fmt.Printf("%s● Proxy bridge active on %s (Mixed HTTP/SOCKS5)%s\n", tester.Green, proxyAddr, tester.Reset)
		} else {
			fmt.Printf("%s● Proxy bridge inactive on %s%s\n", tester.Yellow, proxyAddr, tester.Reset)
		}
	case "run":
		srv := proxy.New(cfg)
		if err := srv.Start(); err != nil {
			log.Fatalf("Failed to start proxy bridge: %v", err)
		}
		log.Printf("[smartnet] Running standalone proxy bridge on %s. Press Ctrl+C to stop.", proxyAddr)
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		srv.Stop()
	case "set":
		if len(os.Args) < 4 {
			fmt.Printf("%sUsage: smartnet proxy set <upstream_url>%s (e.g. socks5://1.2.3.4:1080)\n", tester.Yellow, tester.Reset)
			os.Exit(1)
		}
		active := cfg.GetActive()
		if active == nil {
			fmt.Printf("%sNo active profile configured%s\n", tester.Red, tester.Reset)
			os.Exit(1)
		}
		active.ProxyUpstream = os.Args[3]
		_ = cfg.Save()
		_ = service.Restart()
		fmt.Printf("%sActive profile '%s' proxy upstream set to %s%s\n", tester.Green, active.Name, os.Args[3], tester.Reset)
	default:
		fmt.Printf("%sUnknown proxy action: %s%s\n", tester.Red, action, tester.Reset)
		os.Exit(1)
	}
}

func handleUpdate() {
	fmt.Printf("%s==> Checking and downloading latest SmartNet release...%s\n", tester.Bold, tester.Reset)

	binName := fmt.Sprintf("smartnet-%s-%s", runtime.GOOS, runtime.GOARCH)
	legacyBinName := fmt.Sprintf("smartdns-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		binName += ".exe"
		legacyBinName += ".exe"
	}

	downloadURL := fmt.Sprintf("https://github.com/lovelystarcc/smartnet/releases/latest/download/%s", binName)
	resp, err := http.Get(downloadURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		fallbackURL := fmt.Sprintf("https://github.com/lovelystarcc/smartnet/releases/latest/download/%s", legacyBinName)
		resp, err = http.Get(fallbackURL)
	}

	if err != nil {
		fmt.Printf("%sFailed to fetch release: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("%sFailed to download release: HTTP %d%s\n", tester.Red, resp.StatusCode, tester.Reset)
		os.Exit(1)
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("smartnet_update_%d", os.Getpid()))
	if runtime.GOOS == "windows" {
		tmpFile += ".exe"
	}
	out, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Printf("%sFailed to create temp file: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		_ = os.Remove(tmpFile)
		fmt.Printf("%sFailed to save update: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}
	out.Close()

	// On macOS: apply ad-hoc codesign
	if runtime.GOOS == "darwin" {
		_ = exec.Command("codesign", "-s", "-", "-f", tmpFile).Run()
	}

	// Target binary path
	execPath, err := os.Executable()
	if err != nil {
		if runtime.GOOS == "windows" {
			execPath = "smartnet.exe"
		} else {
			execPath = "/usr/local/bin/smartnet"
		}
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	if runtime.GOOS == "windows" {
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(execPath, oldPath); err != nil {
			_ = os.Remove(tmpFile)
			fmt.Printf("%sFailed to rename active executable: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		if err := os.Rename(tmpFile, execPath); err != nil {
			_ = os.Rename(oldPath, execPath)
			_ = os.Remove(tmpFile)
			fmt.Printf("%sFailed to install new executable: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
	} else {
		// Try atomic rename
		err = os.Rename(tmpFile, execPath)
		if err != nil {
			// Try elevated move if permission denied
			var moveErr error
			if os.Geteuid() == 0 {
				moveErr = exec.Command("mv", "-f", tmpFile, execPath).Run()
			} else {
				cmd := exec.Command("sudo", "mv", "-f", tmpFile, execPath)
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				moveErr = cmd.Run()
			}
			if moveErr != nil {
				_ = os.Remove(tmpFile)
				fmt.Printf("%sFailed to replace binary at %s: %v%s\n", tester.Red, execPath, moveErr, tester.Reset)
				os.Exit(1)
			}
		}
		_ = os.Chmod(execPath, 0755)

		// Create backward-compatibility symlink for smartdns -> smartnet
		dir := filepath.Dir(execPath)
		symlinkTarget := filepath.Join(dir, "smartdns")
		if execPath != symlinkTarget {
			_ = os.Remove(symlinkTarget)
			_ = os.Symlink(execPath, symlinkTarget)
		}
	}

	fmt.Printf("%sUpdated successfully at %s%s\n", tester.Green, execPath, tester.Reset)

	// Check if background service is running and restart it
	running, _, _ := service.Status()
	if running {
		fmt.Printf("Restarting background daemon...\n")
		_ = service.Restart()
		fmt.Printf("%sService reloaded with the new version.%s\n", tester.Green, tester.Reset)
	}
}

func handleCompletion() {
	if len(os.Args) < 3 {
		fmt.Printf(`%sUsage: smartnet completion <fish|zsh|bash|powershell>%s

Setup instructions:
  # Fish (macOS / Linux):
  smartnet completion fish > ~/.config/fish/completions/smartnet.fish

  # Zsh (macOS / Linux):
  mkdir -p ~/.zsh/completion
  smartnet completion zsh > ~/.zsh/completion/_smartnet
  # Ensure 'fpath=(~/.zsh/completion $fpath)' is in ~/.zshrc

  # Bash (Linux):
  smartnet completion bash | sudo tee /etc/bash_completion.d/smartnet >/dev/null

  # PowerShell (Windows / Cross-platform):
  smartnet completion powershell | Out-String | Invoke-Expression
  # Or persist in PowerShell profile: Add to $PROFILE
`, tester.Yellow, tester.Reset)
		os.Exit(1)
	}

	sh := os.Args[2]
	script, err := completion.Generate(sh)
	if err != nil {
		fmt.Printf("%sError: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	fmt.Print(script)
}

func handleFakeIP() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sConfig error: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	active := cfg.GetActive()
	if active == nil {
		fmt.Printf("%sNo active profile configured%s\n", tester.Red, tester.Reset)
		os.Exit(1)
	}

	if len(os.Args) < 3 {
		statusStr := fmt.Sprintf("%sDisabled%s", tester.Yellow, tester.Reset)
		if active.FakeIP {
			statusStr = fmt.Sprintf("%sEnabled%s", tester.Green, tester.Reset)
		}
		alloc, total, err := fakeip.QueryDaemonStats(cfg.ProxyAddr)
		if err != nil {
			alloc, total = fakeip.DefaultPool.Stats()
		}
		fmt.Printf("\n%sFake-IP Engine (RFC 6598 - 198.18.0.0/15)%s\n", tester.Bold, tester.Reset)
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf(" Active Profile     : %s%s%s\n", tester.Cyan, active.Name, tester.Reset)
		fmt.Printf(" State              : %s\n", statusStr)
		fmt.Printf(" Pool Allocated     : %d / %d addresses\n", alloc, total)
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf("Usage:\n  smartnet fakeip on     - Enable Fake-IP mode (0ms instant DNS)\n  smartnet fakeip off    - Disable Fake-IP mode (standard DoH resolution)\n  smartnet fakeip clear  - Clear allocated Fake-IP cache\n\n")
		return
	}

	action := strings.ToLower(os.Args[2])
	switch action {
	case "on", "enable":
		active.FakeIP = true
		_ = cfg.Save()
		_ = service.Restart()
		fmt.Printf("%sFake-IP mode enabled for profile '%s'. Daemon reloaded.%s\n", tester.Green, active.Name, tester.Reset)
	case "off", "disable":
		active.FakeIP = false
		_ = fakeip.ClearDaemon(cfg.ProxyAddr)
		fakeip.DefaultPool.Clear()
		_ = cfg.Save()
		_ = service.Restart()
		network.FlushDNSCache()
		fmt.Printf("%sFake-IP mode disabled for profile '%s'. Daemon reloaded & DNS cache flushed.%s\n", tester.Yellow, active.Name, tester.Reset)
	case "clear":
		_ = fakeip.ClearDaemon(cfg.ProxyAddr)
		fakeip.DefaultPool.Clear()
		network.FlushDNSCache()
		fmt.Printf("%sFake-IP pool cleared & DNS cache flushed.%s\n", tester.Green, tester.Reset)
	case "status":
		alloc, total, err := fakeip.QueryDaemonStats(cfg.ProxyAddr)
		daemonNote := ""
		if err != nil {
			alloc, total = fakeip.DefaultPool.Stats()
			daemonNote = " (daemon unreachable)"
		}
		fmt.Printf("Fake-IP: profile '%s', active: %v, allocated: %d / %d%s\n", active.Name, active.FakeIP, alloc, total, daemonNote)
	default:
		fmt.Printf("%sUnknown fakeip action: %s%s (use: on, off, status, clear)\n", tester.Red, action, tester.Reset)
		os.Exit(1)
	}
}

func handleBypass() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sConfig error: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	active := cfg.GetActive()
	if active == nil {
		fmt.Printf("%sNo active profile configured%s\n", tester.Red, tester.Reset)
		os.Exit(1)
	}

	if len(os.Args) < 3 || os.Args[2] == "list" {
		fmt.Printf("\n%sSplit DNS Bypass Rules (Direct local resolution)%s\n", tester.Bold, tester.Reset)
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf(" Default suffixes : %s\n", strings.Join(rules.DefaultBypassSuffixes, ", "))
		fmt.Printf(" Default services : %s, ...\n", strings.Join(rules.DefaultDomesticServices[:8], ", "))
		if len(active.BypassDomains) > 0 {
			fmt.Printf(" Custom bypass    : %s%s%s\n", tester.Cyan, strings.Join(active.BypassDomains, ", "), tester.Reset)
		} else {
			fmt.Printf(" Custom bypass    : None (add using 'smartnet bypass add <domain>')\n")
		}
		if len(active.ProxyDomains) > 0 {
			fmt.Printf(" Force proxy      : %s%s%s\n", tester.Yellow, strings.Join(active.ProxyDomains, ", "), tester.Reset)
		}
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf("Usage:\n  smartnet bypass add <domain>     - Add domain/suffix to bypass\n  smartnet bypass remove <domain>  - Remove domain from bypass\n  smartnet bypass list             - Show current rules\n\n")
		return
	}

	action := strings.ToLower(os.Args[2])
	switch action {
	case "add":
		if len(os.Args) < 4 {
			fmt.Printf("%sUsage: smartnet bypass add <domain>%s\n", tester.Yellow, tester.Reset)
			os.Exit(1)
		}
		domain := os.Args[3]
		_ = cfg.AddBypassDomain(active.Name, domain)
		_ = cfg.Save()
		_ = service.Restart()
		fmt.Printf("%sAdded '%s' to bypass list for profile '%s'. Daemon reloaded.%s\n", tester.Green, domain, active.Name, tester.Reset)
	case "remove", "rm", "delete":
		if len(os.Args) < 4 {
			fmt.Printf("%sUsage: smartnet bypass remove <domain>%s\n", tester.Yellow, tester.Reset)
			os.Exit(1)
		}
		domain := os.Args[3]
		_ = cfg.RemoveBypassDomain(active.Name, domain)
		_ = cfg.Save()
		_ = service.Restart()
		fmt.Printf("%sRemoved '%s' from bypass list for profile '%s'. Daemon reloaded.%s\n", tester.Green, domain, active.Name, tester.Reset)
	default:
		fmt.Printf("%sUnknown bypass action: %s%s (use: add, remove, list)\n", tester.Red, action, tester.Reset)
		os.Exit(1)
	}
}

func handleTUN() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sConfig error: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	active := cfg.GetActive()
	if active == nil {
		fmt.Printf("%sNo active profile configured%s\n", tester.Red, tester.Reset)
		os.Exit(1)
	}

	if len(os.Args) < 3 {
		statusStr := fmt.Sprintf("%sDisabled%s", tester.Yellow, tester.Reset)
		if active.TUN {
			statusStr = fmt.Sprintf("%sEnabled%s", tester.Green, tester.Reset)
		}
		fmt.Printf("\n%sVirtual TUN Adapter (Fake-IP Transparent Proxy)%s\n", tester.Bold, tester.Reset)
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf(" Active Profile     : %s%s%s\n", tester.Cyan, active.Name, tester.Reset)
		fmt.Printf(" State              : %s\n", statusStr)
		fmt.Printf(" Subnet Routing     : 198.18.0.0/15 (Fake-IP tun2socks)\n")
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf("Usage:\n  smartnet tun on      - Enable Fake-IP TUN mode (routes 198.18.0.0/15 via TUN)\n  smartnet tun off     - Disable TUN mode\n  smartnet tun status  - Show TUN adapter status\n\n")
		return
	}

	action := strings.ToLower(os.Args[2])
	switch action {
	case "on", "enable":
		active.TUN = true
		active.FakeIP = true // TUN requires Fake-IP to route domains into 198.18.0.0/15
		_ = cfg.Save()
		_ = service.Restart()
		network.FlushDNSCache()
		fmt.Printf("%sTUN mode enabled for profile '%s'. Fake-IP enabled. Daemon reloaded.%s\n", tester.Green, active.Name, tester.Reset)
		fmt.Println("  Domain traffic resolves into 198.18.0.0/15 and routes via TUN transparently. Direct IP connections bypass the tunnel.")
	case "off", "disable":
		active.TUN = false
		active.FakeIP = false
		fakeip.DefaultPool.Clear()
		_ = cfg.Save()
		_ = service.Restart()
		network.FlushDNSCache()
		fmt.Printf("%sTUN mode disabled for profile '%s'. Fake-IP cleared & daemon reloaded.%s\n", tester.Yellow, active.Name, tester.Reset)
	case "status":
		statusStr := "disabled"
		if active.TUN {
			statusStr = "enabled"
		}
		fmt.Printf("TUN mode: profile '%s', state: %s (198.18.0.0/15)\n", active.Name, statusStr)
	default:
		fmt.Printf("%sUnknown tun action: %s%s (use: on, off, status)\n", tester.Red, action, tester.Reset)
		os.Exit(1)
	}
}

func handleDNS() {
	if len(os.Args) < 3 {
		fmt.Printf(`%sSmartNet DNS Management%s

Usage:
  smartnet dns on [profile]   - Enable DNS on active network interface
  smartnet dns off            - Disable DNS (restore DHCP)
  smartnet dns toggle         - Toggle DNS on/off
  smartnet dns status         - Show DNS status
`, tester.Bold, tester.Reset)
		return
	}

	sub := strings.ToLower(os.Args[2])
	var rest []string
	if len(os.Args) > 3 {
		rest = os.Args[3:]
	}
	switch sub {
	case "on", "enable":
		handleOnWithArgs(rest)
	case "off", "disable":
		handleOff()
	case "toggle":
		handleToggleWithArgs(rest)
	case "status":
		handleStatus()
	default:
		fmt.Printf("%sUnknown dns command: %s%s (use: on, off, toggle, status)\n", tester.Red, sub, tester.Reset)
		os.Exit(1)
	}
}

func handleVPN() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("%sConfig error: %v%s\n", tester.Red, err, tester.Reset)
		os.Exit(1)
	}

	active := cfg.GetActive()
	if active == nil {
		fmt.Printf("%sNo active profile configured%s\n", tester.Red, tester.Reset)
		os.Exit(1)
	}

	if len(os.Args) < 3 {
		statusStr := fmt.Sprintf("%s● Inactive%s", tester.Yellow, tester.Reset)
		if active.VPN {
			serverDesc := "configured"
			if active.VLESS != nil {
				serverDesc = fmt.Sprintf("%s:%d (SNI: %s)", active.VLESS.Server, active.VLESS.Port, active.VLESS.ServerName)
			}
			tunNote := ""
			if active.TUN {
				tunNote = ", TUN transparent mode"
			}
			statusStr = fmt.Sprintf("%s● Active%s (%s%s)", tester.Green, tester.Reset, serverDesc, tunNote)
		} else if active.VLESS != nil {
			statusStr = fmt.Sprintf("%s● Ready%s (%s:%d)", tester.Cyan, tester.Reset, active.VLESS.Server, active.VLESS.Port)
		}

		fmt.Printf("\n%sVPN & Anti-Censorship Tunnel (VLESS-Reality)%s\n", tester.Bold, tester.Reset)
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf(" Active Profile     : %s%s%s\n", tester.Cyan, active.Name, tester.Reset)
		fmt.Printf(" State              : %s\n", statusStr)
		if active.VLESS != nil {
			fmt.Printf(" VLESS Server       : %s:%d\n", active.VLESS.Server, active.VLESS.Port)
			fmt.Printf(" Camouflage (SNI)   : %s\n", active.VLESS.ServerName)
			if active.VLESS.Flow != "" {
				fmt.Printf(" Flow               : %s\n", active.VLESS.Flow)
			}
			if active.VLESS.PublicKey != "" {
				fmt.Printf(" Reality Public Key : %s\n", active.VLESS.PublicKey)
			}
		} else {
			fmt.Printf(" VLESS Config       : %sNot configured%s\n", tester.Yellow, tester.Reset)
		}
		fmt.Println(tester.Dim + "─────────────────────────────────────────────────────────────────" + tester.Reset)
		fmt.Printf("Usage:\n")
		fmt.Printf("  smartnet vpn on                 - Enable VPN (VLESS + TUN + Fake-IP in 1 click)\n")
		fmt.Printf("  smartnet vpn off                - Disable VPN and TUN adapter\n")
		fmt.Printf("  smartnet vpn toggle             - Toggle VPN on/off\n")
		fmt.Printf("  smartnet vpn set <vless://...>  - Configure VLESS Reality server URI\n")
		fmt.Printf("  smartnet vpn status             - Show current VPN tunnel status\n\n")
		fmt.Printf("Advanced (Granular Controls):\n")
		fmt.Printf("  smartnet vpn on --no-tun        - Enable VLESS for proxy bridge only (127.0.0.1:7890)\n")
		fmt.Printf("  smartnet tun on|off|status      - Independent TUN adapter control\n")
		fmt.Printf("  smartnet fakeip on|off|status   - Independent Fake-IP engine control\n\n")
		return
	}

	action := strings.ToLower(os.Args[2])
	switch action {
	case "on", "enable":
		if active.VLESS == nil {
			fmt.Printf("%sNo VLESS configuration found for profile '%s'.%s\nConfigure it first:\n  smartnet vpn set vless://uuid@server:port?security=reality&sni=...&pbk=...\n", tester.Yellow, active.Name, tester.Reset)
			os.Exit(1)
		}

		noTun := false
		for _, arg := range os.Args[3:] {
			if arg == "--no-tun" || arg == "--proxy-only" {
				noTun = true
			}
		}

		active.VPN = true
		if !noTun {
			active.TUN = true
			active.FakeIP = true
		} else {
			tunWasActive := active.TUN
			active.TUN = false
			active.FakeIP = false
			if tunWasActive {
				fakeip.DefaultPool.Clear()
				network.FlushDNSCache()
			}
		}

		_ = cfg.Save()
		_ = service.Restart()

		if !noTun {
			iface, err := network.ActiveInterface()
			if err != nil {
				iface = "Wi-Fi"
			}
			_ = network.EnsureRouteBypass(active.Upstream)
			if err := ensureServiceReadyAndSetDNS(iface); err != nil {
				fmt.Printf("%sError activating VPN: %v%s\n", tester.Red, err, tester.Reset)
				active.VPN = false
				active.TUN = false
				active.FakeIP = false
				_ = cfg.Save()
				_ = network.ResetDNSServers(iface)
				os.Exit(1)
			}
		}

		fmt.Printf("%sVLESS-Reality VPN enabled for profile '%s'.%s\n", tester.Green, active.Name, tester.Reset)
		if !noTun {
			fmt.Printf("  • Mode        : %sFake-IP Transparent Proxy%s (198.18.0.0/15, domain traffic routed via TUN)\n", tester.Bold, tester.Reset)
			fmt.Printf("  • Server      : %s:%d (SNI: %s)\n", active.VLESS.Server, active.VLESS.Port, active.VLESS.ServerName)
			fmt.Printf("  • Adapter     : Virtual TUN + Fake-IP (198.18.0.0/15)\n")
			fmt.Printf("  • System DNS  : 127.0.0.1 (active)\n")
			fmt.Printf("  • Note        : Raw IP connections and pre-cached IPs bypass TUN proxy\n")
		} else {
			fmt.Printf("  • Mode        : %sProxy Backend Only%s (127.0.0.1:7890, TUN disabled)\n", tester.Cyan, tester.Reset)
			fmt.Printf("  • Server      : %s:%d (SNI: %s)\n", active.VLESS.Server, active.VLESS.Port, active.VLESS.ServerName)
		}

	case "off", "disable":
		active.VPN = false
		tunWasActive := active.TUN
		active.TUN = false
		active.FakeIP = false
		fakeip.DefaultPool.Clear()
		_ = cfg.Save()
		_ = service.Restart()
		network.FlushDNSCache()
		fmt.Printf("%sVLESS-Reality VPN disabled for profile '%s'.%s\n", tester.Yellow, active.Name, tester.Reset)
		if tunWasActive {
			fmt.Printf("  • TUN transparent proxy adapter disabled.\n")
		}
		fmt.Printf("  • Fake-IP disabled, pool cleared & DNS cache flushed.\n")
		fmt.Printf("  • System DNS remains active for SmartDNS. (Run 'smartnet off' to disable DNS completely)\n")

	case "toggle":
		if active.VPN {
			active.VPN = false
			tunWasActive := active.TUN
			active.TUN = false
			active.FakeIP = false
			fakeip.DefaultPool.Clear()
			_ = cfg.Save()
			_ = service.Restart()
			network.FlushDNSCache()
			fmt.Printf("%sVLESS-Reality VPN disabled for profile '%s'.%s\n", tester.Yellow, active.Name, tester.Reset)
			if tunWasActive {
				fmt.Printf("  • TUN transparent proxy adapter disabled.\n")
			}
			fmt.Printf("  • Fake-IP disabled, pool cleared & DNS cache flushed.\n")
		} else {
			if active.VLESS == nil {
				fmt.Printf("%sNo VLESS configuration found for profile '%s'.%s\nConfigure it first:\n  smartnet vpn set vless://...\n", tester.Yellow, active.Name, tester.Reset)
				os.Exit(1)
			}
			active.VPN = true
			active.TUN = true
			active.FakeIP = true

			_ = cfg.Save()
			_ = service.Restart()

			iface, err := network.ActiveInterface()
			if err != nil {
				iface = "Wi-Fi"
			}
			_ = network.EnsureRouteBypass(active.Upstream)
			if err := ensureServiceReadyAndSetDNS(iface); err != nil {
				fmt.Printf("%sError activating VPN: %v%s\n", tester.Red, err, tester.Reset)
				active.VPN = false
				active.TUN = false
				active.FakeIP = false
				_ = cfg.Save()
				_ = network.ResetDNSServers(iface)
				os.Exit(1)
			}

			fmt.Printf("%sVLESS-Reality VPN enabled for profile '%s'.%s\n", tester.Green, active.Name, tester.Reset)
			fmt.Printf("  • Mode   : Fake-IP Transparent Proxy (198.18.0.0/15, domain traffic routed via TUN)\n")
			fmt.Printf("  • Server : %s:%d (SNI: %s)\n", active.VLESS.Server, active.VLESS.Port, active.VLESS.ServerName)
		}

	case "set":
		if len(os.Args) < 4 {
			fmt.Printf("%sUsage: smartnet vpn set <vless://...>%s\n", tester.Yellow, tester.Reset)
			os.Exit(1)
		}
		rawURL := os.Args[3]
		vlessCfg, err := vless.ParseURL(rawURL)
		if err != nil {
			fmt.Printf("%sError parsing VLESS URL: %v%s\n", tester.Red, err, tester.Reset)
			os.Exit(1)
		}
		active.VLESS = vlessCfg
		_ = cfg.Save()
		_ = service.Restart()
		fmt.Printf("%sVLESS Reality configured for profile '%s':%s\n", tester.Green, active.Name, tester.Reset)
		fmt.Printf("  Server     : %s:%d\n", vlessCfg.Server, vlessCfg.Port)
		fmt.Printf("  Camouflage : %s\n", vlessCfg.ServerName)
		if vlessCfg.Flow != "" {
			fmt.Printf("  Flow       : %s\n", vlessCfg.Flow)
		}
		fmt.Printf("\nRun %ssmartnet vpn on%s to activate the tunnel in 1 click.\n", tester.Cyan, tester.Reset)

	case "status":
		statusStr := "disabled"
		if active.VPN {
			statusStr = "enabled"
		}
		server := "none"
		if active.VLESS != nil {
			server = fmt.Sprintf("%s:%d (SNI: %s)", active.VLESS.Server, active.VLESS.Port, active.VLESS.ServerName)
		}
		tunStr := "disabled"
		if active.TUN {
			tunStr = "enabled"
		}
		fmt.Printf("VPN: profile '%s', state: %s, server: %s, TUN: %s\n", active.Name, statusStr, server, tunStr)

	default:
		fmt.Printf("%sUnknown vpn action: %s%s (use: on, off, toggle, set, status)\n", tester.Red, action, tester.Reset)
		os.Exit(1)
	}
}




