package node

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/models"
	"github.com/Spittingjiu/subgo/internal/subconv"
)

type Service struct{ db *sql.DB }

func New(db *sql.DB) *Service { return &Service{db: db} }

func (s *Service) LocalSourceID() (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM sources WHERE source_type='local' ORDER BY id LIMIT 1`).Scan(&id)
	return id, err
}

func (s *Service) List() ([]models.Node, error) {
	rows, err := s.db.Query(`SELECT n.id,n.source_id,s.name,n.display_no,n.node_hash,n.raw_link,n.node_name,n.protocol,n.enabled,n.created_at,n.updated_at,c.status,c.latency_ms,c.last_error FROM nodes n JOIN sources s ON s.id=n.source_id LEFT JOIN node_connectivity c ON c.node_id=n.id WHERE n.enabled IN (0,1) AND s.enabled=1 ORDER BY n.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Service) CreateLocal(raw, name string) (models.Node, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "://") {
		return models.Node{}, errors.New("valid raw link required")
	}
	sid, err := s.LocalSourceID()
	if err != nil {
		return models.Node{}, err
	}
	p := subconv.ParseRawLink(raw)
	if strings.TrimSpace(name) != "" {
		p.Name = strings.TrimSpace(name)
		raw = subconv.WithName(raw, p.Name)
	}
	h := subconv.StableHash(raw)
	now := time.Now().UTC().Format(time.RFC3339)
	var next int64
	_ = s.db.QueryRow(`SELECT COUNT(*)+1 FROM nodes WHERE source_id=?`, sid).Scan(&next)
	display := fmt.Sprintf("L-%03d", next)
	res, err := s.db.Exec(`INSERT INTO nodes(source_id,display_no,node_hash,raw_link,node_name,protocol,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)`, sid, display, h, raw, p.Name, p.Protocol, now, now)
	if err != nil {
		return models.Node{}, err
	}
	id, _ := res.LastInsertId()
	return s.Get(id)
}

func (s *Service) Get(id int64) (models.Node, error) {
	row := s.db.QueryRow(`SELECT n.id,n.source_id,s.name,n.display_no,n.node_hash,n.raw_link,n.node_name,n.protocol,n.enabled,n.created_at,n.updated_at,c.status,c.latency_ms,c.last_error FROM nodes n JOIN sources s ON s.id=n.source_id LEFT JOIN node_connectivity c ON c.node_id=n.id WHERE n.id=?`, id)
	return scanNode(row)
}
func (s *Service) Toggle(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE nodes SET enabled=?,updated_at=? WHERE id=?`, boolInt(enabled), time.Now().UTC().Format(time.RFC3339), id)
	return err
}
func (s *Service) Rename(id int64, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name required")
	}
	n, err := s.Get(id)
	if err != nil {
		return err
	}
	raw := subconv.WithName(n.RawLink, name)
	_, err = s.db.Exec(`UPDATE nodes SET node_name=?,raw_link=?,node_hash=?,updated_at=? WHERE id=?`, name, raw, subconv.StableHash(raw), time.Now().UTC().Format(time.RFC3339), id)
	return err
}
func (s *Service) DeleteLocal(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nodes WHERE id=? AND source_id=(SELECT id FROM sources WHERE source_type='local' ORDER BY id LIMIT 1)`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("local node not found")
	}
	return nil
}

func scanNode(scanner interface{ Scan(...any) error }) (models.Node, error) {
	var n models.Node
	var enabled int
	var ca, ua string
	var connStatus, connErr sql.NullString
	var connLat sql.NullInt64
	if err := scanner.Scan(&n.ID, &n.SourceID, &n.SourceName, &n.DisplayNo, &n.NodeHash, &n.RawLink, &n.NodeName, &n.Protocol, &enabled, &ca, &ua, &connStatus, &connLat, &connErr); err != nil {
		return n, err
	}
	n.Enabled = enabled == 1
	n.CreatedAt, _ = time.Parse(time.RFC3339, ca)
	n.UpdatedAt, _ = time.Parse(time.RFC3339, ua)
	if connStatus.Valid {
		n.ConnectivityStatus = &connStatus.String
	}
	if connLat.Valid {
		n.ConnectivityLatMs = &connLat.Int64
	}
	if connErr.Valid {
		n.ConnectivityError = &connErr.String
	}
	return n, nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
