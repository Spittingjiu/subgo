package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPanelProxyBaseURL    = "https://subgo-panel.2000319.xyz"
	DefaultPanelProxyTicketTTL  = time.Minute
	DefaultPanelProxySessionTTL = 15 * time.Minute
	MaxPanelProxyTicketTTL      = 2 * time.Minute
	MaxPanelProxySessionTTL     = 30 * time.Minute
)

type Config struct {
	Addr          string
	DBPath        string
	BaseURL       string
	SessionSecret string
	// This is a Host allowlist for additional management UIs, NOT a CORS
	// allowlist: browser requests must still use their own target origin.
	ManagementOrigins    []string
	PanelProxyBaseURL    string
	PanelProxyTicketTTL  time.Duration
	PanelProxySessionTTL time.Duration
	ClashTemplateURL     string
	SourceSyncInterval   time.Duration
}

func Load() Config {
	templateURL := env("SUBGO_CLASH_TEMPLATE_URL", "https://raw.githubusercontent.com/Spittingjiu/mihomo-generic-template/main/clash-template.yaml")
	return Config{
		Addr:                 env("SUBGO_ADDR", "127.0.0.1:8781"),
		DBPath:               env("SUBGO_DB", "data/subgo.db"),
		BaseURL:              env("SUBGO_BASE_URL", ""),
		SessionSecret:        env("SUBGO_SESSION_SECRET", ""),
		ManagementOrigins:    originListEnv("SUBGO_MANAGEMENT_ORIGINS"),
		PanelProxyBaseURL:    env("SUBGO_PANEL_PROXY_BASE_URL", DefaultPanelProxyBaseURL),
		PanelProxyTicketTTL:  securityDurationEnv("SUBGO_PANEL_PROXY_TICKET_TTL", DefaultPanelProxyTicketTTL),
		PanelProxySessionTTL: securityDurationEnv("SUBGO_PANEL_PROXY_SESSION_TTL", DefaultPanelProxySessionTTL),
		ClashTemplateURL:     templateURL,
		SourceSyncInterval:   durationEnv("SUBGO_SOURCE_SYNC_INTERVAL", 5*time.Minute),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if sec, err := strconv.Atoi(v); err == nil && sec > 0 {
		return time.Duration(sec) * time.Second
	}
	return fallback
}

// ValidateSecurity must run before opening the DB or starting workers. Errors
// deliberately name settings, never their values or the signing key.
func (c Config) ValidateSecurity() error {
	if strings.TrimSpace(c.SessionSecret) == "" {
		return errors.New("SUBGO_SESSION_SECRET is required (no development fallback)")
	}
	origins, err := c.ManagementOriginURLs()
	if err != nil {
		return err
	}
	proxy, err := c.PanelProxyOriginURL()
	if err != nil {
		return err
	}
	if proxy != nil {
		for _, origin := range origins {
			// Cookies are host-bound, not port-bound. A different port alone
			// does not provide the required cookie isolation.
			if proxy.Hostname() == origin.Hostname() {
				return errors.New("SUBGO_PANEL_PROXY_BASE_URL must use a different hostname from every management origin")
			}
		}
	}
	if ttl := c.EffectivePanelProxyTicketTTL(); ttl < time.Second || ttl > MaxPanelProxyTicketTTL {
		return errors.New("SUBGO_PANEL_PROXY_TICKET_TTL must be between 1s and 2m")
	}
	if ttl := c.EffectivePanelProxySessionTTL(); ttl < time.Second || ttl > MaxPanelProxySessionTTL {
		return errors.New("SUBGO_PANEL_PROXY_SESSION_TTL must be between 1s and 30m")
	}
	return nil
}

// ParseOrigin accepts an absolute HTTP(S) origin, not an arbitrary URL. A root
// slash is accepted for config convenience, then removed. Credentials, queries,
// fragments and non-root paths are never accepted.
func ParseOrigin(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t ") {
		return nil, errors.New("invalid HTTP origin")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("invalid HTTP origin")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("invalid HTTP origin")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return nil, errors.New("invalid HTTP origin")
	}
	if net.ParseIP(host) == nil {
		if strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
			return nil, errors.New("invalid HTTP origin")
		}
		for _, ch := range host {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
				return nil, errors.New("invalid HTTP origin")
			}
		}
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid HTTP origin")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid HTTP origin")
		}
		port = strconv.Itoa(n)
		if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
			port = ""
		}
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

func (c Config) ManagementOriginURLs() ([]*url.URL, error) {
	var origins []*url.URL
	seen := make(map[string]bool)
	add := func(raw, setting string) error {
		u, err := ParseOrigin(raw)
		if err != nil {
			return errors.New(setting + " must contain absolute HTTP(S) origins without credentials or paths")
		}
		if !seen[u.String()] {
			seen[u.String()] = true
			origins = append(origins, u)
		}
		return nil
	}
	if c.BaseURL != "" {
		if err := add(c.BaseURL, "SUBGO_BASE_URL"); err != nil {
			return nil, err
		}
	}
	for _, origin := range c.ManagementOrigins {
		if err := add(origin, "SUBGO_MANAGEMENT_ORIGINS"); err != nil {
			return nil, err
		}
	}
	return origins, nil
}

func (c Config) PanelProxyOriginURL() (*url.URL, error) {
	if c.PanelProxyBaseURL == "" {
		return nil, nil // explicit in-memory config can disable proxy launch
	}
	u, err := ParseOrigin(c.PanelProxyBaseURL)
	if err != nil || u.Scheme != "https" {
		return nil, errors.New("SUBGO_PANEL_PROXY_BASE_URL must be an independent HTTPS origin without credentials or paths")
	}
	return u, nil
}

func (c Config) EffectivePanelProxyTicketTTL() time.Duration {
	if c.PanelProxyTicketTTL == 0 {
		return DefaultPanelProxyTicketTTL
	}
	return c.PanelProxyTicketTTL
}

func (c Config) EffectivePanelProxySessionTTL() time.Duration {
	if c.PanelProxySessionTTL == 0 {
		return DefaultPanelProxySessionTTL
	}
	return c.PanelProxySessionTTL
}

func originListEnv(key string) []string {
	if raw := os.Getenv(key); raw != "" {
		parts := strings.Split(raw, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts // empty entries fail validation instead of being ignored
	}
	return nil
}

// Malformed security durations fail validation, unlike the legacy scheduler
// helper which falls back. Syntax is Go time.ParseDuration (e.g. 60s or 15m).
func securityDurationEnv(key string, fallback time.Duration) time.Duration {
	if raw := os.Getenv(key); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return -1
		}
		return d
	}
	return fallback
}
