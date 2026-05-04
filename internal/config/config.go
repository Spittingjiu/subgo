package config

import (
	"os"
)

type Config struct {
	Addr    string
	DBPath  string
	BaseURL string
}

func Load() Config {
	return Config{
		Addr:    env("SUBGO_ADDR", "127.0.0.1:8781"),
		DBPath:  env("SUBGO_DB", "data/subgo.db"),
		BaseURL: env("SUBGO_BASE_URL", ""),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
