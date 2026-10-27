package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type VLESSConfig struct {
	Server     string `json:"server"`
	Port       int    `json:"port"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	ShortID    string `json:"short_id,omitempty"`
	SpiderX    string `json:"spider_x,omitempty"`
}

type Profile struct {
	Name           string       `json:"name"`
	Upstream       string       `json:"upstream"`
	BackupUpstream string       `json:"backup_upstream,omitempty"`
	ProxyUpstream  string       `json:"proxy_upstream,omitempty"`
	Bootstrap      []string     `json:"bootstrap,omitempty"`
	Desc           string       `json:"description,omitempty"`
	BypassDomains  []string     `json:"bypass_domains,omitempty"`
	ProxyDomains   []string     `json:"proxy_domains,omitempty"`
	FakeIP         bool         `json:"fake_ip,omitempty"`
	TUN            bool         `json:"tun,omitempty"`
	VPN            bool         `json:"vpn,omitempty"`
	VLESS          *VLESSConfig `json:"vless,omitempty"`
}

type Config struct {
	ActiveProfile string              `json:"active_profile"`
	ListenAddr    string              `json:"listen_addr"`
	ProxyAddr     string              `json:"proxy_addr,omitempty"`
	Profiles      map[string]*Profile `json:"profiles"`
	mu            sync.RWMutex        `json:"-"`
	path          string              `json:"-"`
}

func DefaultConfig() *Config {
	return &Config{
		ActiveProfile: "",
		ListenAddr:    "127.0.0.1:53",
		ProxyAddr:     "127.0.0.1:7890",
		Profiles:      make(map[string]*Profile),
	}
}

func getLegacyConfigPath() string {
	if custom := os.Getenv("SMARTDNS_CONFIG"); custom != "" {
		return custom
	}
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "smartdns", "config.json")
		}
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "smartdns", "config.json")
		}
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, ".smartdns", "config.json")
		}
		return `C:\ProgramData\smartdns\config.json`
	}
	if os.Geteuid() == 0 {
		if runtime.GOOS == "darwin" {
			if u := getConsoleUser(); u != "" {
				userPath := filepath.Join("/Users", u, ".config", "smartdns", "config.json")
				if _, err := os.Stat(userPath); err == nil {
					return userPath
				}
			}
		}
		return "/etc/smartdns/config.json"
	}
	home, err := os.UserHomeDir()
	if err == nil {
		userPath := filepath.Join(home, ".config", "smartdns", "config.json")
		if _, err := os.Stat("/etc/smartdns/config.json"); err == nil {
			if _, err2 := os.Stat(userPath); os.IsNotExist(err2) {
				return "/etc/smartdns/config.json"
			}
		}
		return userPath
	}
	return "/etc/smartdns/config.json"
}

func getConsoleUser() string {
	cmd := exec.Command("stat", "-f", "%Su", "/dev/console")
	out, err := cmd.Output()
	if err == nil {
		u := strings.TrimSpace(string(out))
		if u != "" && u != "root" {
			return u
		}
	}
	return ""
}

func GetLogPath() string {
	if custom := os.Getenv("SMARTNET_LOG"); custom != "" {
		return custom
	}
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "smartnet", "smartnet.log")
		}
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "smartnet", "smartnet.log")
		}
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, ".smartnet", "smartnet.log")
		}
		return filepath.Join(os.TempDir(), "smartnet.log")
	}
	if runtime.GOOS == "darwin" {
		if os.Geteuid() == 0 {
			return "/var/log/smartnet.log"
		}
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, ".config", "smartnet", "smartnet.log")
		}
		return "/var/log/smartnet.log"
	}
	if os.Geteuid() == 0 {
		return "/var/log/smartnet.log"
	}
	home, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(home, ".config", "smartnet", "smartnet.log")
	}
	return "/var/log/smartnet.log"
}

func GetConfigPath() string {
	if custom := os.Getenv("SMARTNET_CONFIG"); custom != "" {
		return custom
	}
	if custom := os.Getenv("SMARTDNS_CONFIG"); custom != "" {
		return custom
	}
	if runtime.GOOS == "windows" {
		// 1. ProgramData shared config (accessible to both user and background daemon)
		if programData := os.Getenv("ProgramData"); programData != "" {
			pdPath := filepath.Join(programData, "smartnet", "config.json")
			if _, err := os.Stat(pdPath); err == nil {
				return pdPath
			}
		}
		// 2. APPDATA roaming
		if appData := os.Getenv("APPDATA"); appData != "" {
			adPath := filepath.Join(appData, "smartnet", "config.json")
			if _, err := os.Stat(adPath); err == nil {
				return adPath
			}
		}
		// 3. User home dir
		home, err := os.UserHomeDir()
		if err == nil {
			userPath := filepath.Join(home, ".config", "smartnet", "config.json")
			if _, err := os.Stat(userPath); err == nil {
				return userPath
			}
			dotPath := filepath.Join(home, ".smartnet", "config.json")
			if _, err := os.Stat(dotPath); err == nil {
				return dotPath
			}
		}
		// 4. Executable directory
		if exe, err := os.Executable(); err == nil {
			exeConfig := filepath.Join(filepath.Dir(exe), "config.json")
			if _, err := os.Stat(exeConfig); err == nil {
				return exeConfig
			}
		}
		// Default creation path: prefer APPDATA if available, then ProgramData
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "smartnet", "config.json")
		}
		if programData := os.Getenv("ProgramData"); programData != "" {
			return filepath.Join(programData, "smartnet", "config.json")
		}
		if err == nil {
			return filepath.Join(home, ".smartnet", "config.json")
		}
		return `C:\ProgramData\smartnet\config.json`
	}
	if os.Geteuid() == 0 {
		if runtime.GOOS == "darwin" {
			if u := getConsoleUser(); u != "" {
				userPath := filepath.Join("/Users", u, ".config", "smartnet", "config.json")
				if _, err := os.Stat(userPath); err == nil {
					return userPath
				}
			}
		}
		return "/etc/smartnet/config.json"
	}
	home, err := os.UserHomeDir()
	if err == nil {
		userPath := filepath.Join(home, ".config", "smartnet", "config.json")
		// If system config exists and user config doesn't, default to system
		if _, err := os.Stat("/etc/smartnet/config.json"); err == nil {
			if _, err2 := os.Stat(userPath); os.IsNotExist(err2) {
				return "/etc/smartnet/config.json"
			}
		}
		return userPath
	}
	return "/etc/smartnet/config.json"
}

func Load() (*Config, error) {
	p := GetConfigPath()
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			// Auto-migration: check if legacy smartdns config exists
			legacyPath := getLegacyConfigPath()
			if legacyData, legacyErr := os.ReadFile(legacyPath); legacyErr == nil {
				cfg := &Config{}
				if jsonErr := json.Unmarshal(legacyData, cfg); jsonErr == nil {
					cfg.path = p
					_ = cfg.Save() // Migrate immediately into smartnet path
					return cfg, nil
				}
			}

			cfg := DefaultConfig()
			cfg.path = p
			_ = cfg.Save()
			return cfg, nil
		}
		return nil, err
	}

	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %s: %w", p, err)
	}
	cfg.path = p

	// Enforce secure permissions on existing config files containing credentials
	if runtime.GOOS != "windows" {
		if fi, statErr := os.Stat(p); statErr == nil && fi.Mode().Perm() != 0600 {
			_ = os.Chmod(p, 0600)
		}
	}

	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*Profile)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:53"
	}
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = "127.0.0.1:7890"
	}
	return cfg, nil
}

func (c *Config) Save() error {
	c.mu.Lock()
	if c.path == "" {
		c.path = GetConfigPath()
	}
	p := c.path
	data, err := json.MarshalIndent(c, "", "  ")
	c.mu.Unlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p)
	permDir := os.FileMode(0700)
	permFile := os.FileMode(0600)
	if err := os.MkdirAll(dir, permDir); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Atomic write: write to temp file, sync, close, then rename
	tmpPath := p + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, permFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary config file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write config data: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to sync config file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close config file: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmpPath, permFile)
		_ = os.Chmod(dir, permDir)
	}
	if err := os.Rename(tmpPath, p); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomically commit config file: %w", err)
	}

	// On Windows, mirror to ProgramData so background scheduled tasks/services can access it
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			pdPath := filepath.Join(programData, "smartnet", "config.json")
			if !strings.EqualFold(p, pdPath) {
				_ = os.MkdirAll(filepath.Dir(pdPath), 0700)
				pdTmp := pdPath + ".tmp"
				if pf, err := os.OpenFile(pdTmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
					_, _ = pf.Write(data)
					_ = pf.Sync()
					_ = pf.Close()
					_ = os.Rename(pdTmp, pdPath)
				}
			}
		}
	}

	return nil
}

func (c *Config) GetPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.path
}

func (c *Config) GetActive() *Profile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Profiles[c.ActiveProfile]
}

func (c *Config) SetActive(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	c.ActiveProfile = name
	return nil
}

func (c *Config) AddProfile(p *Profile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	if p.Upstream == "" {
		return fmt.Errorf("upstream URL cannot be empty")
	}
	if len(p.Bootstrap) == 0 {
		p.Bootstrap = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	c.Profiles[p.Name] = p
	if c.ActiveProfile == "" {
		c.ActiveProfile = p.Name
	}
	return nil
}

func (c *Config) RemoveProfile(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.Profiles[name]; !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	delete(c.Profiles, name)
	if c.ActiveProfile == name {
		c.ActiveProfile = ""
		for k := range c.Profiles {
			c.ActiveProfile = k
			break
		}
	}
	return nil
}

func (c *Config) SetFakeIP(name string, enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	p.FakeIP = enabled
	return nil
}

func (c *Config) SetTUN(name string, enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	p.TUN = enabled
	return nil
}

func (c *Config) AddBypassDomain(name, domain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	d := strings.ToLower(strings.TrimSpace(domain))
	for _, existing := range p.BypassDomains {
		if strings.EqualFold(existing, d) {
			return nil
		}
	}
	p.BypassDomains = append(p.BypassDomains, d)
	return nil
}

func (c *Config) RemoveBypassDomain(name, domain string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	d := strings.ToLower(strings.TrimSpace(domain))
	var updated []string
	for _, existing := range p.BypassDomains {
		if !strings.EqualFold(existing, d) {
			updated = append(updated, existing)
		}
	}
	p.BypassDomains = updated
	return nil
}

func (c *Config) SetVPN(name string, enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	p.VPN = enabled
	return nil
}

func (c *Config) SetVLESS(name string, vless *VLESSConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.Profiles[name]
	if !ok {
		return fmt.Errorf("profile '%s' not found", name)
	}
	p.VLESS = vless
	return nil
}
