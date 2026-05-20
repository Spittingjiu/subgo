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
	"github.com/Spittingjiu/subgo/internal/subconv"
)

type Service struct{ db *sql.DB }

func New(db *sql.DB) *Service { return &Service{db: db} }

func (s *Service) List(base string) ([]models.Subscription, error) {
	rows, err := s.db.Query(`SELECT id,name,token,source_ids_json,node_ids_json,enabled,auto_prune_unreachable,access_count,last_accessed_at,created_at,updated_at FROM subscriptions ORDER BY id DESC`)
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
		if err := s.fillSourceNames(&sub); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}
func (s *Service) Create(name string, nodeHashes []string, sourceIDs []int64, autoPruneUnreachable bool) (models.Subscription, error) {
	if strings.TrimSpace(name) == "" {
		name = "默认订阅"
	}
	token := randToken()
	now := time.Now().UTC().Format(time.RFC3339)
	nj, _ := json.Marshal(nodeHashes)
	sj, _ := json.Marshal(sourceIDs)
	res, err := s.db.Exec(`INSERT INTO subscriptions(name,token,source_ids_json,node_ids_json,enabled,auto_prune_unreachable,created_at,updated_at) VALUES(?,?,?,?,1,?,?,?)`, name, token, string(sj), string(nj), boolInt(autoPruneUnreachable), now, now)
	if err != nil {
		return models.Subscription{}, err
	}
	id, _ := res.LastInsertId()
	sub, err := s.Get(id, "")
	if err != nil {
		return models.Subscription{}, err
	}
	if sub.NodeHashes == nil {
		sub.NodeHashes = []string{}
	}
	if sub.SourceIDs == nil {
		sub.SourceIDs = []int64{}
	}
	return sub, nil
}
func (s *Service) Get(id int64, base string) (models.Subscription, error) {
	row := s.db.QueryRow(`SELECT id,name,token,source_ids_json,node_ids_json,enabled,auto_prune_unreachable,access_count,last_accessed_at,created_at,updated_at FROM subscriptions WHERE id=?`, id)
	return scanSub(row, base)
}
func (s *Service) Update(id int64, name string, nodeHashes []string, sourceIDs []int64, enabled *bool, autoPruneUnreachable bool) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name required")
	}
	nj, _ := json.Marshal(nodeHashes)
	sj, _ := json.Marshal(sourceIDs)
	enabledVal := -1
	if enabled != nil {
		enabledVal = boolInt(*enabled)
	}
	_, err := s.db.Exec(`UPDATE subscriptions SET name=?,source_ids_json=?,node_ids_json=?,enabled=CASE WHEN ?=-1 THEN enabled ELSE ? END,auto_prune_unreachable=?,updated_at=? WHERE id=?`, name, string(sj), string(nj), enabledVal, enabledVal, boolInt(autoPruneUnreachable), time.Now().UTC().Format(time.RFC3339), id)
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
	if sub.AutoPruneUnreachable {
		q += ` AND NOT EXISTS (SELECT 1 FROM node_connectivity nc WHERE nc.node_id=n.id AND nc.status='fail')`
	}
	if len(sub.NodeHashes) > 0 {
		q += ` AND n.node_hash IN (` + placeholders(len(sub.NodeHashes)) + `)`
		for _, h := range sub.NodeHashes {
			args = append(args, h)
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

func (s *Service) Clash(token, clientIP, ua string, clashTemplate []byte) (string, error) {
	plain, err := s.PlainLinks(token, clientIP, ua)
	if err != nil {
		return "", err
	}
	if len(clashTemplate) > 0 {
		return subconv.ClashYAMLFromTemplate(subconv.ParseSubscriptionText(plain), clashTemplate)
	}
	return subconv.ClashYAML(subconv.ParseSubscriptionText(plain))
}

func (s *Service) getByToken(token string) (models.Subscription, error) {
	row := s.db.QueryRow(`SELECT id,name,token,source_ids_json,node_ids_json,enabled,auto_prune_unreachable,access_count,last_accessed_at,created_at,updated_at FROM subscriptions WHERE token=?`, token)
	return scanSub(row, "")
}

func (s *Service) fillSourceNames(sub *models.Subscription) error {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(sub.SourceIDs) > 0 {
		q := `SELECT name FROM sources WHERE id IN (` + placeholders(len(sub.SourceIDs)) + `) ORDER BY id ASC`
		args := make([]any, 0, len(sub.SourceIDs))
		for _, id := range sub.SourceIDs {
			args = append(args, id)
		}
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			add(name)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	if len(sub.NodeHashes) > 0 {
		q := `SELECT DISTINCT s.name FROM nodes n JOIN sources s ON s.id=n.source_id WHERE n.node_hash IN (` + placeholders(len(sub.NodeHashes)) + `) ORDER BY s.id ASC`
		args := make([]any, 0, len(sub.NodeHashes))
		for _, h := range sub.NodeHashes {
			args = append(args, h)
		}
		rows, err := s.db.Query(q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			add(name)
		}
		if err := rows.Err(); err != nil {
			return err
		}
	}
	sub.SourceNames = names
	return nil
}
func scanSub(scanner interface{ Scan(...any) error }, base string) (models.Subscription, error) {
	var sub models.Subscription
	var enabled int
	var autoPrune int
	var la sql.NullString
	var ca, ua string
	if err := scanner.Scan(&sub.ID, &sub.Name, &sub.Token, &sub.SourceIDsJSON, &sub.NodeHashesJSON, &enabled, &autoPrune, &sub.AccessCount, &la, &ca, &ua); err != nil {
		return sub, err
	}
	sub.Enabled = enabled == 1
	sub.AutoPruneUnreachable = autoPrune == 1
	_ = json.Unmarshal([]byte(sub.SourceIDsJSON), &sub.SourceIDs)
	_ = json.Unmarshal([]byte(sub.NodeHashesJSON), &sub.NodeHashes)
	if sub.SourceIDs == nil {
		sub.SourceIDs = []int64{}
	}
	if sub.NodeHashes == nil {
		sub.NodeHashes = []string{}
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

// RepairOrphanNodeHashes removes subscription node_hash entries that no longer
// match any node in the nodes table. Returns the number of orphan entries removed.
func (s *Service) RepairOrphanNodeHashes() (pruned int, err error) {
	rows, err := s.db.Query(`SELECT id, node_ids_json FROM subscriptions`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var existing map[string]bool
	for rows.Next() {
		var subID int64
		var nodeHashesJSON string
		if err := rows.Scan(&subID, &nodeHashesJSON); err != nil {
			return pruned, err
		}
		var nodeHashes []string
		json.Unmarshal([]byte(nodeHashesJSON), &nodeHashes)

		valid := make([]string, 0, len(nodeHashes))
		for _, nh := range nodeHashes {
			if existing == nil {
				existing = make(map[string]bool)
				existingRows, err2 := s.db.Query(`SELECT node_hash FROM nodes`)
				if err2 != nil {
					return pruned, err2
				}
				for existingRows.Next() {
					var eh string
					existingRows.Scan(&eh)
					existing[eh] = true
				}
				existingRows.Close()
			}
			if existing[nh] {
				valid = append(valid, nh)
			}
		}
		if len(valid) < len(nodeHashes) {
			newJSON, _ := json.Marshal(valid)
			s.db.Exec(`UPDATE subscriptions SET node_ids_json=? WHERE id=?`, string(newJSON), subID)
			pruned += len(nodeHashes) - len(valid)
		}
	}
	return pruned, rows.Err()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
