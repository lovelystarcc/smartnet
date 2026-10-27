package tester

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"smartnet/pkg/fakeip"
	"smartnet/pkg/network"
	"smartnet/pkg/rules"

	"github.com/miekg/dns"
)

const (
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Red     = "\033[31m"
	Cyan    = "\033[36m"
	Magenta = "\033[35m"
	Reset   = "\033[0m"
)

var DefaultDomains = []string{
	"cloudaicompanion.googleapis.com",
	"chatgpt.com",
	"claude.ai",
	"gemini.google.com",
	"spotify.com",
	"canva.com",
	"notion.so",
	"rutracker.org",
	"yandex.ru",
	"google.com",
}

type Result struct {
	Domain   string
	DNSMs    float64
	Resolved string
	IsProxy  bool
	TLSMs    float64
	HTTPCode int
	Error    string
}

func visibleLen(s string) int {
	re := regexp.MustCompile(`\033\[[0-9;]*m`)
	return len(re.ReplaceAllString(s, ""))
}

func pad(s string, width int) string {
	vl := visibleLen(s)
	if vl >= width {
		return s
	}
	return s + string(make([]byte, width-vl))
}

func padLeft(s string, width int) string {
	vl := visibleLen(s)
	if vl >= width {
		return s
	}
	return string(make([]byte, width-vl)) + s
}

func Run(domains []string, vpsHost string) {
	if len(domains) == 0 {
		domains = DefaultDomains
	}

	targetIP := vpsHost
	if ip := network.ParseIPFromHostname(vpsHost); ip != nil {
		targetIP = ip.String()
	} else if vpsHost != "" {
		if ips, err := net.LookupIP(vpsHost); err == nil && len(ips) > 0 {
			targetIP = ips[0].String()
		}
	}

	colDomain := 33
	colDNS := 13
	colRoute := 29
	colTLS := 13
	colHTTP := 8

	header := fmt.Sprintf(" %s %s %s %s %s",
		pad(Bold+"DOMAIN"+Reset, colDomain),
		pad(Bold+"DNS RESOLVE"+Reset, colDNS),
		pad(Bold+"ROUTE / IP"+Reset, colRoute),
		pad(Bold+"TLS PING"+Reset, colTLS),
		pad(Bold+"HTTP"+Reset, colHTTP),
	)
	sep := fmt.Sprintf(" %s %s %s %s %s",
		Dim+stringsRepeat("─", 32)+Reset,
		Dim+stringsRepeat("─", 12)+Reset,
		Dim+stringsRepeat("─", 28)+Reset,
		Dim+stringsRepeat("─", 12)+Reset,
		Dim+stringsRepeat("─", 7)+Reset,
	)

	fmt.Println(header)
	fmt.Println(sep)

	start := time.Now()
	var wg sync.WaitGroup
	results := make([]*Result, len(domains))

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			results[idx] = testDomain(domain, targetIP)
		}(i, d)
	}
	wg.Wait()

	var totalDNS, totalTLS float64
	var countDNS, countTLS int

	for _, r := range results {
		dStr := pad(r.Domain, colDomain)

		// DNS format
		dnsStr := ""
		if r.DNSMs < 0 {
			dnsStr = fmt.Sprintf("%sTIMEOUT%s", Red, Reset)
		} else {
			totalDNS += r.DNSMs
			countDNS++
			if r.DNSMs < 50 {
				dnsStr = fmt.Sprintf("%s%5.1f ms%s", Green, r.DNSMs, Reset)
			} else if r.DNSMs < 200 {
				dnsStr = fmt.Sprintf("%s%5.1f ms%s", Yellow, r.DNSMs, Reset)
			} else {
				dnsStr = fmt.Sprintf("%s%5.1f ms%s", Red, r.DNSMs, Reset)
			}
		}

		// Route format
		routeStr := ""
		if r.Resolved != "" && fakeip.DefaultPool.IsFakeIP(net.ParseIP(r.Resolved)) {
			routeStr = fmt.Sprintf("%sFake-IP%s %s(%s)%s", Cyan, Reset, Dim, r.Resolved, Reset)
		} else if r.IsProxy {
			routeStr = fmt.Sprintf("%sSmartNet%s %s(%s)%s", Magenta, Reset, Dim, r.Resolved, Reset)
		} else if rules.ShouldBypass(r.Domain, nil, nil) {
			routeStr = fmt.Sprintf("%sDirect/Split%s %s(%s)%s", Green, Reset, Dim, r.Resolved, Reset)
		} else if r.Resolved == "FAIL" || r.Resolved == "" {
			routeStr = fmt.Sprintf("%sError%s", Red, Reset)
		} else {
			routeStr = fmt.Sprintf("%sDirect IP%s (%s)", Dim, Reset, r.Resolved)
		}

		// TLS format
		tlsStr := ""
		if r.TLSMs <= 0 {
			tlsStr = fmt.Sprintf("%s   -    %s", Dim, Reset)
		} else {
			totalTLS += r.TLSMs
			countTLS++
			if r.TLSMs < 150 {
				tlsStr = fmt.Sprintf("%s%5.0f ms%s", Green, r.TLSMs, Reset)
			} else if r.TLSMs < 350 {
				tlsStr = fmt.Sprintf("%s%5.0f ms%s", Yellow, r.TLSMs, Reset)
			} else {
				tlsStr = fmt.Sprintf("%s%5.0f ms%s", Red, r.TLSMs, Reset)
			}
		}

		// HTTP format
		httpStr := ""
		if r.HTTPCode == 0 {
			httpStr = fmt.Sprintf("%sERR%s", Red, Reset)
		} else if r.HTTPCode == 200 || r.HTTPCode == 301 || r.HTTPCode == 302 || r.HTTPCode == 404 {
			httpStr = fmt.Sprintf("%s%d%s", Green, r.HTTPCode, Reset)
		} else if r.HTTPCode == 403 || r.HTTPCode == 421 {
			httpStr = fmt.Sprintf("%s%d%s", Cyan, r.HTTPCode, Reset)
		} else {
			httpStr = fmt.Sprintf("%s%d%s", Yellow, r.HTTPCode, Reset)
		}

		line := fmt.Sprintf(" %s %s %s %s %s",
			dStr,
			pad(dnsStr, colDNS),
			pad(routeStr, colRoute),
			pad(tlsStr, colTLS),
			pad(httpStr, colHTTP),
		)
		fmt.Println(line)
	}

	fmt.Println()
	fmt.Println(Dim + stringsRepeat("─", 77) + Reset)

	avgDNS := 0.0
	if countDNS > 0 {
		avgDNS = totalDNS / float64(countDNS)
	}
	avgTLS := 0.0
	if countTLS > 0 {
		avgTLS = totalTLS / float64(countTLS)
	}

	fmt.Printf(" Avg DNS: %s%.1f ms%s | Avg TLS: %s%.0f ms%s | Total time: %.2f s\n\n",
		Green, avgDNS, Reset,
		Green, avgTLS, Reset,
		time.Since(start).Seconds(),
	)
}

func stringsRepeat(s string, count int) string {
	res := ""
	for i := 0; i < count; i++ {
		res += s
	}
	return res
}

func testDomain(domain, vpsIP string) *Result {
	res := &Result{Domain: domain, DNSMs: -1}

	// 1. DNS Query to 127.0.0.1:53
	c := new(dns.Client)
	c.Timeout = 2 * time.Second
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	t0 := time.Now()
	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err == nil && r != nil {
		res.DNSMs = float64(time.Since(t0).Microseconds()) / 1000.0
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				res.Resolved = a.A.String()
				if vpsIP != "" && res.Resolved == vpsIP {
					res.IsProxy = true
				}
				break
			}
		}
	}

	// 2. HTTP / TLS probe
	reqURL := fmt.Sprintf("https://%s", domain)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reqURL, nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")

	tlsStart := time.Now()
	var tlsDuration time.Duration

	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tlsStart = time.Now()
	resp, err := client.Do(req)
	tlsDuration = time.Since(tlsStart)

	if err == nil {
		res.HTTPCode = resp.StatusCode
		res.TLSMs = float64(tlsDuration.Microseconds()) / 1000.0
		resp.Body.Close()
	}

	return res
}
