package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr               string
	DBPath             string
	BaseURL            string
	SessionSecret      string
	ClashTemplateURL   string
	SourceSyncInterval time.Duration
}

func Load() Config {
	templateURL := env("SUBGO_CLASH_TEMPLATE_URL", "https://raw.githubusercontent.com/Spittingjiu/mihomo-generic-template/main/clash-template.yaml")
	return Config{
		Addr:               env("SUBGO_ADDR", "127.0.0.1:8781"),
		DBPath:             env("SUBGO_DB", "data/subgo.db"),
		BaseURL:            env("SUBGO_BASE_URL", ""),
		SessionSecret:      env("SUBGO_SESSION_SECRET", ""),
		ClashTemplateURL:   templateURL,
		SourceSyncInterval: durationEnv("SUBGO_SOURCE_SYNC_INTERVAL", 5*time.Minute),
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
