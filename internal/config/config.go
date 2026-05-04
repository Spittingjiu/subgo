package config

import (
	"os"
)

type Config struct {
	Addr             string
	DBPath           string
	BaseURL          string
	SessionSecret    string
	ClashTemplateURL string
}

func Load() Config {
	templateURL := env("SUBGO_CLASH_TEMPLATE_URL", "https://raw.githubusercontent.com/Spittingjiu/mihomo-generic-template/main/clash-template.yaml")
	return Config{
		Addr:             env("SUBGO_ADDR", "127.0.0.1:8781"),
		DBPath:           env("SUBGO_DB", "data/subgo.db"),
		BaseURL:          env("SUBGO_BASE_URL", ""),
		SessionSecret:    env("SUBGO_SESSION_SECRET", ""),
		ClashTemplateURL: templateURL,
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
