package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type DB struct{ *sql.DB }

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	d, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	wrapped := &DB{DB: d}
	if err := wrapped.Migrate(); err != nil {
		_ = d.Close()
		return nil, err
	}
	return wrapped, nil
}

func (d *DB) Migrate() error {
	stmts := []string{
		`PRAGMA foreign_keys=ON`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS admin_settings (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sources (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, source_type TEXT NOT NULL, panel_url TEXT NOT NULL DEFAULT '', panel_token TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, last_sync_at TEXT, last_sync_status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE, display_no TEXT NOT NULL, node_hash TEXT NOT NULL UNIQUE, raw_link TEXT NOT NULL, node_name TEXT NOT NULL, protocol TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, token TEXT NOT NULL UNIQUE, source_ids_json TEXT NOT NULL DEFAULT '[]', node_ids_json TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, access_count INTEGER NOT NULL DEFAULT 0, last_accessed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS subscription_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL, subscription_id INTEGER NOT NULL, subscription_name TEXT NOT NULL, route_type TEXT NOT NULL, client_ip TEXT NOT NULL, user_agent TEXT NOT NULL, created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_source ON nodes(source_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sub_logs_created ON subscription_logs(created_at DESC)`,
	}
	for _, s := range stmts {
		if _, err := d.Exec(s); err != nil {
			return fmt.Errorf("migrate: %w sql=%s", err, s)
		}
	}
	return d.ensureDefaults()
}

func (d *DB) ensureDefaults() error {
	now := time.Now().UTC().Format(time.RFC3339)
	var c int
	if err := d.QueryRow(`SELECT COUNT(*) FROM admin_settings WHERE id=1`).Scan(&c); err != nil {
		return err
	}
	if c == 0 {
		h, err := bcrypt.GenerateFromPassword([]byte(env("SUBGO_ADMIN_PASS", "admin123")), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := d.Exec(`INSERT INTO admin_settings(id,username,password_hash,created_at,updated_at) VALUES(1,?,?,?,?)`, env("SUBGO_ADMIN_USER", "admin"), string(h), now, now); err != nil {
			return err
		}
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM sources WHERE source_type='local'`).Scan(&c); err != nil {
		return err
	}
	if c == 0 {
		_, err := d.Exec(`INSERT INTO sources(name,source_type,panel_url,enabled,last_sync_status,created_at,updated_at) VALUES('本地节点','local','',1,'local',?,?)`, now, now)
		return err
	}
	return nil
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func ParseTimePtr(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func MustTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty time")
	}
	return time.Parse(time.RFC3339, s)
}
