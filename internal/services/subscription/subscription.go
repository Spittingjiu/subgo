package subscription

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/models"
)

type Service struct{ db *sql.DB }

func New(db *sql.DB) *Service { return &Service{db: db} }

func (s *Service) List(base string) ([]models.Subscription, error) {
	rows, err := s.db.Query(`SELECT id,name,token,source_ids_json,node_ids_json,enabled,access_count,last_accessed_at,created_at,updated_at FROM subscriptions ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Subscription
	for rows.Next() {
		sub, err := scanSub(rows, base)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}
func (s *Service) Create(name string, nodeIDs, sourceIDs []int64) (models.Subscription, error) {
	if strings.TrimSpace(name) == "" {
		name = "默认订阅"
	}
	token := randToken()
	now := time.Now().UTC().Format(time.RFC3339)
	nj, _ := json.Marshal(nodeIDs)
	sj, _ := json.Marshal(sourceIDs)
	res, err := s.db.Exec(`INSERT INTO subscriptions(name,token,source_ids_json,node_ids_json,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)`, name, token, string(sj), string(nj), now, now)
	if err != nil {
		return models.Subscription{}, err
	}
	id, _ := res.LastInsertId()
	sub, err := s.Get(id, "")
	if err != nil {
		return models.Subscription{}, err
	}
	if sub.NodeIDs == nil {
		sub.NodeIDs = []int64{}
	}
	if sub.SourceIDs == nil {
		sub.SourceIDs = []int64{}
	}
	return sub, nil
}
func (s *Service) Get(id int64, base string) (models.Subscription, error) {
	row := s.db.QueryRow(`SELECT id,name,token,source_ids_json,node_ids_json,enabled,access_count,last_accessed_at,created_at,updated_at FROM subscriptions WHERE id=?`, id)
	return scanSub(row, base)
}
func (s *Service) Update(id int64, name string, nodeIDs, sourceIDs []int64, enabled bool) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name required")
	}
	nj, _ := json.Marshal(nodeIDs)
	sj, _ := json.Marshal(sourceIDs)
	_, err := s.db.Exec(`UPDATE subscriptions SET name=?,source_ids_json=?,node_ids_json=?,enabled=?,updated_at=? WHERE id=?`, name, string(sj), string(nj), boolInt(enabled), time.Now().UTC().Format(time.RFC3339), id)
	return err
}
func (s *Service) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM subscriptions WHERE id=?`, id)
	return err
}

func (s *Service) PlainLinks(token, clientIP, ua string) (string, error) {
	sub, err := s.getByToken(token)
	if err != nil {
		return "", err
	}
	if !sub.Enabled {
		return "", errors.New("subscription disabled")
	}
	q := `SELECT n.raw_link FROM nodes n JOIN sources s ON s.id=n.source_id WHERE n.enabled=1 AND s.enabled=1`
	args := []any{}
	if len(sub.NodeIDs) > 0 {
		q += ` AND n.id IN (` + placeholders(len(sub.NodeIDs)) + `)`
		for _, id := range sub.NodeIDs {
			args = append(args, id)
		}
	} else if len(sub.SourceIDs) > 0 {
		q += ` AND n.source_id IN (` + placeholders(len(sub.SourceIDs)) + `)`
		for _, id := range sub.SourceIDs {
			args = append(args, id)
		}
	}
	q += ` ORDER BY n.id ASC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var links []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return "", err
		}
		links = append(links, raw)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = s.db.Exec(`UPDATE subscriptions SET access_count=access_count+1,last_accessed_at=? WHERE id=?`, now, sub.ID)
	_, _ = s.db.Exec(`INSERT INTO subscription_logs(token,subscription_id,subscription_name,route_type,client_ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?)`, token, sub.ID, sub.Name, "plain", clientIP, ua, now)
	return strings.Join(links, "\n") + "\n", nil
}

func (s *Service) getByToken(token string) (models.Subscription, error) {
	row := s.db.QueryRow(`SELECT id,name,token,source_ids_json,node_ids_json,enabled,access_count,last_accessed_at,created_at,updated_at FROM subscriptions WHERE token=?`, token)
	return scanSub(row, "")
}
func scanSub(scanner interface{ Scan(...any) error }, base string) (models.Subscription, error) {
	var sub models.Subscription
	var enabled int
	var la sql.NullString
	var ca, ua string
	if err := scanner.Scan(&sub.ID, &sub.Name, &sub.Token, &sub.SourceIDsJSON, &sub.NodeIDsJSON, &enabled, &sub.AccessCount, &la, &ca, &ua); err != nil {
		return sub, err
	}
	sub.Enabled = enabled == 1
	_ = json.Unmarshal([]byte(sub.SourceIDsJSON), &sub.SourceIDs)
	_ = json.Unmarshal([]byte(sub.NodeIDsJSON), &sub.NodeIDs)
	if sub.SourceIDs == nil {
		sub.SourceIDs = []int64{}
	}
	if sub.NodeIDs == nil {
		sub.NodeIDs = []int64{}
	}
	if la.Valid && la.String != "" {
		t, _ := time.Parse(time.RFC3339, la.String)
		sub.LastAccessedAt = &t
	}
	sub.CreatedAt, _ = time.Parse(time.RFC3339, ca)
	sub.UpdatedAt, _ = time.Parse(time.RFC3339, ua)
	if base != "" {
		sub.PlainURL = strings.TrimRight(base, "/") + "/sub/" + sub.Token
	}
	return sub, nil
}
func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	xs := make([]string, n)
	for i := range xs {
		xs[i] = "?"
	}
	return strings.Join(xs, ",")
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
