// Package config loads dnsd's settings.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is dnsd's configuration file.
type Config struct {
	// Database is where observations and cursors are kept.
	Database string `json:"database"`

	// Sources are the resolvers to read. Two entries for a keepalived pair:
	// both are polled, both feed one store, and a failover is invisible
	// because nothing in the baseline is per-node.
	Sources []Source `json:"sources"`

	// FlushInterval is how often accumulated counters are written. Shorter
	// means less lost on an unclean stop; longer means fewer writes.
	FlushInterval Duration `json:"flush_interval"`

	// RetainDays bounds the store. Zero keeps everything, which is a
	// reasonable default: counters are small.
	RetainDays int `json:"retain_days"`

	// Thresholds tune the operational detectors. These need a threshold
	// rather than a baseline, which is why they work on day one.
	Thresholds Thresholds `json:"thresholds"`
}

// Source describes one resolver.
type Source struct {
	// Type selects the implementation. Only "technitium" exists today.
	Type string `json:"type"`

	// Name identifies this resolver in stored records. It must be stable
	// across restarts — it ends up in the data and in cursor keys.
	Name string `json:"name"`

	// URL is the resolver's API root, e.g. "http://192.168.253.105:5380".
	URL string `json:"url"`

	// Token authenticates to it. Prefer TokenFile so a secret is not sitting
	// in a config file that gets copied around.
	Token string `json:"token,omitempty"`

	// TokenFile reads the token from disk at startup, which is what an
	// Ansible deploy should use.
	TokenFile string `json:"token_file,omitempty"`

	// PollInterval defaults to the source's own default. It must stay well
	// inside the resolver's log retention: the log is a ring, and anything
	// that ages out between polls is gone.
	PollInterval Duration `json:"poll_interval,omitempty"`
}

// Thresholds are the operational detector limits.
type Thresholds struct {
	// QueriesPerMinute flags a client asking more than this. A normal client
	// on this network sits far below; the loop found on 2026-08-04 ran at 176.
	QueriesPerMinute float64 `json:"queries_per_minute"`

	// SingleLabelPerMinute flags search-domain expansion running hot — the
	// specific shape of that loop, where a bare name is tried before the
	// search domain is appended and always answers NXDOMAIN.
	SingleLabelPerMinute float64 `json:"single_label_per_minute"`

	// NXDomainRatio flags a client whose lookups mostly fail, which is either
	// a misconfiguration or a domain-generation algorithm.
	NXDomainRatio float64 `json:"nxdomain_ratio"`

	// MinQueries is the volume below which a client is not judged at all.
	// Without it, a host that asks twice and misses once reads as a 50%
	// failure rate.
	MinQueries int64 `json:"min_queries"`
}

// Defaults are deliberately loose. A detector that cries wolf on day one gets
// switched off, and these can only be tightened once there is a week of data
// showing what normal looks like.
func Defaults() Config {
	return Config{
		Database:      "/var/lib/dnsgate/dnsgate.db",
		FlushInterval: Duration(time.Minute),
		Thresholds: Thresholds{
			QueriesPerMinute:     60,
			SingleLabelPerMinute: 10,
			NXDomainRatio:        0.5,
			MinQueries:           200,
		},
	}
}

// Load reads a config file, applying defaults for anything unset.
func Load(path string) (Config, error) {
	cfg := Defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	// Decode over the defaults so an omitted field keeps its default rather
	// than becoming a zero that silently disables a detector.
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.resolveTokens(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) resolveTokens() error {
	for i := range c.Sources {
		s := &c.Sources[i]
		if s.TokenFile == "" {
			continue
		}
		raw, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return fmt.Errorf("source %q: read token file: %w", s.Name, err)
		}
		s.Token = strings.TrimSpace(string(raw))
	}
	return nil
}

// Validate checks the config is usable before anything starts.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Database) == "" {
		return fmt.Errorf("database path is required")
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("at least one source is required")
	}
	if time.Duration(c.FlushInterval) <= 0 {
		return fmt.Errorf("flush_interval must be positive")
	}

	seen := map[string]bool{}
	for _, s := range c.Sources {
		switch {
		case strings.TrimSpace(s.Name) == "":
			return fmt.Errorf("every source needs a name")
		case s.Type != "technitium":
			return fmt.Errorf("source %q: unknown type %q", s.Name, s.Type)
		case strings.TrimSpace(s.URL) == "":
			return fmt.Errorf("source %q: url is required", s.Name)
		case strings.TrimSpace(s.Token) == "":
			return fmt.Errorf("source %q: token or token_file is required", s.Name)
		}
		// Names key the cursor table, so a duplicate would make two resolvers
		// share a read position and each skip the other's queries.
		if seen[s.Name] {
			return fmt.Errorf("duplicate source name %q", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// Duration is a time.Duration that unmarshals from a string like "5m".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"5m\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}
