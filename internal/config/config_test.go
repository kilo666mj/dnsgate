package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadMinimal(t *testing.T) {
	path := write(t, `{
	  "database": "/tmp/dnsgate.db",
	  "sources": [
	    {"type": "technitium", "name": "dnsc1n1", "url": "http://192.168.253.104:5380", "token": "a"},
	    {"type": "technitium", "name": "dnsc1n2", "url": "http://192.168.253.105:5380", "token": "b"}
	  ]
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(cfg.Sources))
	}
	// Omitted fields must keep their defaults, not become zeroes that
	// silently switch a detector off.
	if time.Duration(cfg.FlushInterval) != time.Minute {
		t.Errorf("flush_interval = %v, want the default", time.Duration(cfg.FlushInterval))
	}
	if cfg.Thresholds.QueriesPerMinute != 60 || cfg.Thresholds.MinQueries != 200 {
		t.Errorf("thresholds = %+v, want defaults", cfg.Thresholds)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	path := write(t, `{
	  "database": "/tmp/x.db",
	  "flush_interval": "30s",
	  "retain_days": 90,
	  "sources": [{"type":"technitium","name":"n","url":"http://x:5380","token":"t","poll_interval":"2m"}],
	  "thresholds": {"queries_per_minute": 120, "min_queries": 500}
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if time.Duration(cfg.FlushInterval) != 30*time.Second {
		t.Errorf("flush = %v", time.Duration(cfg.FlushInterval))
	}
	if time.Duration(cfg.Sources[0].PollInterval) != 2*time.Minute {
		t.Errorf("poll = %v", time.Duration(cfg.Sources[0].PollInterval))
	}
	if cfg.RetainDays != 90 || cfg.Thresholds.QueriesPerMinute != 120 {
		t.Errorf("cfg = %+v", cfg)
	}
	// An unset threshold inside a provided block still keeps its default.
	if cfg.Thresholds.NXDomainRatio != 0.5 {
		t.Errorf("nxdomain_ratio = %v, want the default to survive a partial block",
			cfg.Thresholds.NXDomainRatio)
	}
}

// A token in a config file gets copied around; a token file can be deployed
// with its own permissions.
func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("  secret-token\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	path := write(t, `{
	  "database": "/tmp/x.db",
	  "sources": [{"type":"technitium","name":"n","url":"http://x:5380","token_file":"`+tokenPath+`"}]
	}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sources[0].Token != "secret-token" {
		t.Errorf("token = %q, want it read and trimmed", cfg.Sources[0].Token)
	}
}

func TestValidateRejects(t *testing.T) {
	base := func() Config {
		c := Defaults()
		c.Sources = []Source{{Type: "technitium", Name: "n", URL: "http://x:5380", Token: "t"}}
		return c
	}
	for name, mangle := range map[string]func(*Config){
		"no database":  func(c *Config) { c.Database = "" },
		"no sources":   func(c *Config) { c.Sources = nil },
		"no name":      func(c *Config) { c.Sources[0].Name = "" },
		"unknown type": func(c *Config) { c.Sources[0].Type = "bind" },
		"no url":       func(c *Config) { c.Sources[0].URL = "" },
		"no token":     func(c *Config) { c.Sources[0].Token = "" },
		"zero flush":   func(c *Config) { c.FlushInterval = 0 },
	} {
		c := base()
		mangle(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// Names key the cursor table. Two sources sharing a name would share a read
// position and each skip the other's queries.
func TestValidateRejectsDuplicateNames(t *testing.T) {
	c := Defaults()
	c.Sources = []Source{
		{Type: "technitium", Name: "dup", URL: "http://a:5380", Token: "t"},
		{Type: "technitium", Name: "dup", URL: "http://b:5380", Token: "t"},
	}
	if err := c.Validate(); err == nil {
		t.Error("want an error for duplicate source names")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("want an error for a missing config")
	}
}

func TestDurationRejectsBareNumber(t *testing.T) {
	path := write(t, `{"database":"/tmp/x.db","flush_interval":60,
	  "sources":[{"type":"technitium","name":"n","url":"http://x:5380","token":"t"}]}`)
	if _, err := Load(path); err == nil {
		t.Error(`want an error: 60 is ambiguous, "60s" is not`)
	}
}
