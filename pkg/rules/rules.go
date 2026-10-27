package rules

import (
	"strings"
)

// DefaultBypassSuffixes includes national TLDs and local intranet suffixes
var DefaultBypassSuffixes = []string{
	".ru",
	".рф",
	".su",
	".by",
	".kz",
	".local",
	".lan",
	".home",
	".internal",
}

// DefaultCaptiveDomains contains OS captive portal and connectivity checks
var DefaultCaptiveDomains = []string{
	"captive.apple.com",
	"connectivitycheck.gstatic.com",
	"connectivitycheck.android.com",
	"detectportal.firefox.com",
	"msftconnecttest.com",
	"ipv6.msftconnecttest.com",
	"www.msftconnecttest.com",
	"networkcheck.kde.org",
}

// DefaultDomesticServices contains popular domestic domains (even on international TLDs)
var DefaultDomesticServices = []string{
	"vk.com",
	"vk.me",
	"userapi.com",
	"yandex.ru",
	"ya.ru",
	"yandex.net",
	"kinopoisk.ru",
	"sber.ru",
	"sberbank.ru",
	"sberbank.com",
	"tbank.ru",
	"tinkoff.ru",
	"gosuslugi.ru",
	"nalog.ru",
	"mos.ru",
	"ozon.ru",
	"wildberries.ru",
	"avito.ru",
	"mail.ru",
	"ok.ru",
	"dzen.ru",
	"rutube.ru",
	"rbc.ru",
	"lenta.ru",
	"2gis.ru",
	"hh.ru",
	"cian.ru",
}

func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(d, ".")
}

// MatchesRule checks if domain equals or is a subdomain of pattern
func MatchesRule(domain, pattern string) bool {
	d := normalizeDomain(domain)
	p := normalizeDomain(pattern)
	if strings.HasPrefix(p, "*.") {
		p = p[1:]
	}
	if strings.HasPrefix(p, ".") {
		return d == p[1:] || strings.HasSuffix(d, p)
	}
	return d == p || strings.HasSuffix(d, "."+p)
}

// IsLocalOrCaptive checks if domain is local or a captive portal check
func IsLocalOrCaptive(domain string) bool {
	d := normalizeDomain(domain)
	if d == "localhost" {
		return true
	}
	for _, suffix := range []string{".local", ".lan", ".home", ".internal"} {
		if strings.HasSuffix(d, suffix) {
			return true
		}
	}
	for _, cd := range DefaultCaptiveDomains {
		if d == cd || strings.HasSuffix(d, "."+cd) {
			return true
		}
	}
	return false
}

// ShouldBypass determines if a domain should bypass DoH and resolve via local DNS
func ShouldBypass(domain string, customBypass []string, customProxy []string) bool {
	d := normalizeDomain(domain)
	if d == "" {
		return true
	}

	// 1. Explicit user override: force proxy
	for _, p := range customProxy {
		if MatchesRule(d, p) {
			return false
		}
	}

	// 2. Local & captive portal checks
	if IsLocalOrCaptive(d) {
		return true
	}

	// 3. User custom bypass list
	for _, b := range customBypass {
		if MatchesRule(d, b) {
			return true
		}
	}

	// 4. Default domestic services
	for _, ds := range DefaultDomesticServices {
		if MatchesRule(d, ds) {
			return true
		}
	}

	// 5. Default bypass suffixes (.ru, .рф, .su, etc.)
	for _, suffix := range DefaultBypassSuffixes {
		if strings.HasSuffix(d, suffix) {
			return true
		}
	}

	return false
}
