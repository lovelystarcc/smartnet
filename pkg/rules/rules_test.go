package rules

import (
	"testing"
)

func TestShouldBypass(t *testing.T) {
	tests := []struct {
		domain       string
		customBypass []string
		customProxy  []string
		expected     bool
	}{
		// Blocked / Foreign target domains -> DO NOT BYPASS (go to DoH)
		{"chatgpt.com", nil, nil, false},
		{"claude.ai", nil, nil, false},
		{"gemini.google.com", nil, nil, false},
		{"cloudaicompanion.googleapis.com", nil, nil, false},
		{"spotify.com", nil, nil, false},
		{"notion.so", nil, nil, false},
		{"rutracker.org", nil, nil, false},

		// Domestic TLDs -> BYPASS (go direct/local)
		{"yandex.ru", nil, nil, true},
		{"mail.ru", nil, nil, true},
		{"kremlin.ru", nil, nil, true},
		{"президент.рф", nil, nil, true},
		{"test.su", nil, nil, true},
		{"onliner.by", nil, nil, true},
		{"tengrinews.kz", nil, nil, true},

		// Domestic services on .com -> BYPASS
		{"vk.com", nil, nil, true},
		{"api.vk.com", nil, nil, true},
		{"sberbank.com", nil, nil, true},

		// Local & captive -> BYPASS
		{"router.local", nil, nil, true},
		{"mybox.lan", nil, nil, true},
		{"localhost", nil, nil, true},
		{"captive.apple.com", nil, nil, true},

		// Custom bypass
		{"example.com", []string{"example.com"}, nil, true},
		{"sub.example.com", []string{"example.com"}, nil, true},
		{"example.com", []string{"*.example.com"}, nil, true},
		{"sub.example.com", []string{"*.example.com"}, nil, true},
		{"deep.sub.example.com", []string{"*.example.com"}, nil, true},
		{"notexample.com", []string{"*.example.com"}, nil, false},

		// Custom force proxy override (takes precedence over bypass)
		{"music.yandex.ru", nil, []string{"music.yandex.ru"}, false},
	}

	for _, tc := range tests {
		result := ShouldBypass(tc.domain, tc.customBypass, tc.customProxy)
		if result != tc.expected {
			t.Errorf("ShouldBypass(%q) = %v; expected %v", tc.domain, result, tc.expected)
		}
	}
}
