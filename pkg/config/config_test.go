package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if cfg.ActiveProfile != "" {
		t.Errorf("expected empty active profile, got %q", cfg.ActiveProfile)
	}
	if cfg.ListenAddr != "127.0.0.1:53" {
		t.Errorf("expected listen addr 127.0.0.1:53, got %q", cfg.ListenAddr)
	}
	if cfg.Profiles == nil {
		t.Error("expected non-nil profiles map")
	}
}

func TestAddProfile(t *testing.T) {
	cfg := DefaultConfig()

	// Empty name
	err := cfg.AddProfile(&Profile{Name: "", Upstream: "https://example.com/dns-query"})
	if err == nil {
		t.Error("expected error for empty profile name, got nil")
	}

	// Empty upstream
	err = cfg.AddProfile(&Profile{Name: "test", Upstream: ""})
	if err == nil {
		t.Error("expected error for empty upstream, got nil")
	}

	// Valid profile with default bootstraps
	p1 := &Profile{
		Name:     "profile1",
		Upstream: "https://example.com/dns-query",
		Desc:     "Profile 1 Description",
	}
	if err := cfg.AddProfile(p1); err != nil {
		t.Fatalf("unexpected error adding profile: %v", err)
	}
	if len(p1.Bootstrap) != 2 || p1.Bootstrap[0] != "1.1.1.1:53" {
		t.Errorf("expected default bootstraps to be populated, got %v", p1.Bootstrap)
	}

	// Valid profile with custom bootstraps
	p2 := &Profile{
		Name:      "profile2",
		Upstream:  "https://dns.google/dns-query",
		Bootstrap: []string{"8.8.8.8:53"},
	}
	if err := cfg.AddProfile(p2); err != nil {
		t.Fatalf("unexpected error adding profile2: %v", err)
	}
	if len(p2.Bootstrap) != 1 || p2.Bootstrap[0] != "8.8.8.8:53" {
		t.Errorf("expected custom bootstraps preserved, got %v", p2.Bootstrap)
	}
}

func TestSetActiveAndGetActive(t *testing.T) {
	cfg := DefaultConfig()

	_ = cfg.AddProfile(&Profile{Name: "p1", Upstream: "https://p1.example/dns-query"})
	_ = cfg.AddProfile(&Profile{Name: "p2", Upstream: "https://p2.example/dns-query"})

	if err := cfg.SetActive("p1"); err != nil {
		t.Fatalf("unexpected error setting active profile: %v", err)
	}

	active := cfg.GetActive()
	if active == nil || active.Name != "p1" {
		t.Fatalf("expected active profile 'p1', got %v", active)
	}

	// Nonexistent profile
	if err := cfg.SetActive("nonexistent"); err == nil {
		t.Error("expected error setting nonexistent active profile, got nil")
	}
}

func TestRemoveProfile(t *testing.T) {
	cfg := DefaultConfig()

	_ = cfg.AddProfile(&Profile{Name: "p1", Upstream: "https://p1.example/dns-query"})
	_ = cfg.AddProfile(&Profile{Name: "p2", Upstream: "https://p2.example/dns-query"})
	_ = cfg.SetActive("p1")

	// Removing nonexistent
	if err := cfg.RemoveProfile("nonexistent"); err == nil {
		t.Error("expected error removing nonexistent profile, got nil")
	}

	// Removing non-active
	if err := cfg.RemoveProfile("p2"); err != nil {
		t.Fatalf("unexpected error removing p2: %v", err)
	}
	if _, exists := cfg.Profiles["p2"]; exists {
		t.Error("expected p2 to be removed from profiles map")
	}
	if cfg.ActiveProfile != "p1" {
		t.Errorf("expected active profile to remain p1, got %q", cfg.ActiveProfile)
	}

	// Removing active profile should fallback to remaining profile
	_ = cfg.AddProfile(&Profile{Name: "p3", Upstream: "https://p3.example/dns-query"})
	if err := cfg.RemoveProfile("p1"); err != nil {
		t.Fatalf("unexpected error removing p1: %v", err)
	}
	if cfg.ActiveProfile != "p3" {
		t.Errorf("expected active profile to fallback to p3, got %q", cfg.ActiveProfile)
	}

	// Removing the last remaining profile should reset ActiveProfile to ""
	if err := cfg.RemoveProfile("p3"); err != nil {
		t.Fatalf("unexpected error removing last profile p3: %v", err)
	}
	if cfg.ActiveProfile != "" {
		t.Errorf("expected active profile to be empty after removing last profile, got %q", cfg.ActiveProfile)
	}

	// Adding a profile when ActiveProfile is empty should set it active
	if err := cfg.AddProfile(&Profile{Name: "pNew", Upstream: "https://new.example/dns-query"}); err != nil {
		t.Fatalf("unexpected error adding pNew: %v", err)
	}
	if cfg.ActiveProfile != "pNew" {
		t.Errorf("expected active profile to be set to pNew, got %q", cfg.ActiveProfile)
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	t.Setenv("SMARTDNS_CONFIG", configPath)

	if got := GetConfigPath(); got != configPath {
		t.Errorf("GetConfigPath() = %q; want %q", got, configPath)
	}

	// Initial load when file does not exist creates default config and saves it
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error loading non-existent config: %v", err)
	}

	_ = cfg.AddProfile(&Profile{
		Name:           "custom",
		Upstream:       "https://doh.custom.net/dns-query",
		BackupUpstream: "https://1.1.1.1/dns-query",
		Desc:           "Custom profile",
	})
	_ = cfg.SetActive("custom")
	cfg.ListenAddr = "127.0.0.1:5353"

	if err := cfg.Save(); err != nil {
		t.Fatalf("unexpected error saving config: %v", err)
	}

	// Re-load config
	loadedCfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error reloading config: %v", err)
	}

	if loadedCfg.ActiveProfile != "custom" {
		t.Errorf("expected active profile 'custom', got %q", loadedCfg.ActiveProfile)
	}
	if loadedCfg.ListenAddr != "127.0.0.1:5353" {
		t.Errorf("expected listen addr '127.0.0.1:5353', got %q", loadedCfg.ListenAddr)
	}
	p := loadedCfg.GetActive()
	if p == nil || p.Upstream != "https://doh.custom.net/dns-query" {
		t.Errorf("expected loaded active profile upstream 'https://doh.custom.net/dns-query', got %v", p)
	}
	if p == nil || p.BackupUpstream != "https://1.1.1.1/dns-query" {
		t.Errorf("expected loaded backup upstream 'https://1.1.1.1/dns-query', got %v", p)
	}
	if loadedCfg.GetPath() != configPath {
		t.Errorf("expected path %q, got %q", configPath, loadedCfg.GetPath())
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("failed to stat config file: %v", err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("expected config file permissions 0600, got %o", fi.Mode().Perm())
		}
	}
}

func TestLoadCorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	corruptPath := filepath.Join(tmpDir, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("invalid json {{"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SMARTDNS_CONFIG", corruptPath)

	_, err := Load()
	if err == nil {
		t.Error("expected error loading corrupt config, got nil")
	}
}

func TestGetLogPath(t *testing.T) {
	p := GetLogPath()
	if p == "" {
		t.Fatal("expected non-empty log path")
	}
}

