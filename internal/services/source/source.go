package source

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/subconv"
)

type Service struct {
	db     *sql.DB
	client *http.Client
}
type Source struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Type           string  `json:"source_type"`
	PanelURL       string  `json:"panel_url"`
	PanelToken     string  `json:"-"`
	Enabled        bool    `json:"enabled"`
	LastSyncAt     *string `json:"last_sync_at,omitempty"`
	LastSyncStatus string  `json:"last_sync_status"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

func New(db *sql.DB) *Service {
	return &Service{db: db, client: &http.Client{Timeout: 12 * time.Second}}
}
func (s *Service) List() ([]Source, error) {
	rows, err := s.db.Query(`SELECT id,name,source_type,panel_url,panel_token,enabled,last_sync_at,last_sync_status,created_at,updated_at FROM sources ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var x Source
		var en int
		var l sql.NullString
		if err := rows.Scan(&x.ID, &x.Name, &x.Type, &x.PanelURL, &x.PanelToken, &en, &l, &x.LastSyncStatus, &x.CreatedAt, &x.UpdatedAt); err != nil {
			return nil, err
		}
		x.Enabled = en == 1
		if l.Valid {
			v := l.String
			x.LastSyncAt = &v
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Service) Get(id int64) (Source, error) {
	var x Source
	var en int
	var l sql.NullString
	err := s.db.QueryRow(`SELECT id,name,source_type,panel_url,panel_token,enabled,last_sync_at,last_sync_status,created_at,updated_at FROM sources WHERE id=?`, id).Scan(&x.ID, &x.Name, &x.Type, &x.PanelURL, &x.PanelToken, &en, &l, &x.LastSyncStatus, &x.CreatedAt, &x.UpdatedAt)
	x.Enabled = en == 1
	if l.Valid {
		v := l.String
		x.LastSyncAt = &v
	}
	return x, err
}
func (s *Service) Create(name, typ, panelURL, token string) (Source, error) {
	typ = strings.TrimSpace(typ)
	if typ == "" {
		typ = "cf_sub"
	}
	if typ == "local" {
		return Source{}, errors.New("local source is managed by system")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO sources(name,source_type,panel_url,panel_token,enabled,last_sync_status,created_at,updated_at) VALUES(?,?,?,?,1,'pending',?,?)`, name, typ, panelURL, token, now, now)
	if err != nil {
		return Source{}, err
	}
	id, _ := res.LastInsertId()
	return s.Get(id)
}
func (s *Service) Update(id int64, name, panelURL, token string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE sources SET name=?,panel_url=?,panel_token=?,enabled=?,updated_at=? WHERE id=? AND source_type!='local'`, name, panelURL, token, boolInt(enabled), time.Now().UTC().Format(time.RFC3339), id)
	return err
}
func (s *Service) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sources WHERE id=? AND source_type!='local'`, id)
	return err
}
func (s *Service) SyncAll() map[int64]string {
	rows, _ := s.db.Query(`SELECT id FROM sources WHERE source_type!='local' AND enabled=1 ORDER BY id`)
	if rows == nil {
		return map[int64]string{}
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		_ = rows.Scan(&id)
		r := s.Sync(id)
		if r != nil {
			out[id] = r.Error()
		} else {
			out[id] = "ok"
		}
	}
	return out
}
func (s *Service) Sync(id int64) error {
	src, err := s.Get(id)
	if err != nil {
		return err
	}
	if src.Type == "local" {
		return nil
	}
	links, err := s.fetchLinks(src)
	status := "ok"
	if err != nil {
		status = err.Error()
	} else if len(links) == 0 {
		status = "no nodes"
		err = errors.New(status)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = s.db.Exec(`UPDATE sources SET last_sync_at=?,last_sync_status=?,updated_at=? WHERE id=?`, now, status, now, id)
	if err != nil {
		return err
	}
	return s.upsertNodes(id, links)
}
func (s *Service) fetchLinks(src Source) ([]string, error) {
	switch src.Type {
	case "cf_sub", "raw_sub", "sui_api":
		return s.fetchSubURL(src.PanelURL, src.PanelToken)
	case "sbui":
		u := src.PanelURL
		if !strings.Contains(u, "/api/v1/sub/") {
			u = strings.TrimRight(u, "/") + "/api/v1/sub/default"
		}
		return s.fetchSubURL(u, src.PanelToken)
	default:
		return nil, fmt.Errorf("unsupported source type %s", src.Type)
	}
}
func (s *Service) fetchSubURL(raw, token string) ([]string, error) {
	if err := assertURLSafe(raw); err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", raw, nil)
	req.Header.Set("User-Agent", "subgo/0.2")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return subconv.ParseSubscriptionText(string(b)), nil
}
func (s *Service) upsertNodes(sourceID int64, links []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	seen := map[string]bool{}
	for _, raw := range links {
		p := subconv.ParseRawLink(raw)
		h := subconv.StableHash(raw)
		seen[h] = true
		var exists int64
		_ = tx.QueryRow(`SELECT id FROM nodes WHERE node_hash=?`, h).Scan(&exists)
		if exists > 0 {
			_, err = tx.Exec(`UPDATE nodes SET source_id=?,raw_link=?,node_name=?,protocol=?,updated_at=? WHERE id=?`, sourceID, raw, p.Name, p.Protocol, now, exists)
		} else {
			var next int64
			_ = tx.QueryRow(`SELECT COUNT(*)+1 FROM nodes WHERE source_id=?`, sourceID).Scan(&next)
			disp := fmt.Sprintf("S%d-%03d", sourceID, next)
			_, err = tx.Exec(`INSERT INTO nodes(source_id,display_no,node_hash,raw_link,node_name,protocol,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`, sourceID, disp, h, raw, p.Name, p.Protocol, now, now)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
func assertURLSafe(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only http/https allowed")
	}
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("blocked private ip %s", ip.String())
		}
		if ip.String() == "169.254.169.254" {
			return errors.New("blocked metadata ip")
		}
	}
	return nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
