package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	NodeCount      int     `json:"node_count"`
	SUIFlavor      string  `json:"sui_flavor,omitempty"`
}
type Inbound struct {
	ID        int64  `json:"id"`
	DisplayID string `json:"display_id"`
	Remark    string `json:"remark"`
	Protocol  string `json:"protocol"`
	Port      any    `json:"port"`
	Enable    bool   `json:"enable"`
	Raw       any    `json:"raw,omitempty"`
}

func New(db *sql.DB) *Service {
	return &Service{db: db, client: &http.Client{Timeout: 12 * time.Second}}
}
func (s *Service) List() ([]Source, error) {
	rows, err := s.db.Query(`SELECT s.id,s.name,s.source_type,s.panel_url,s.panel_token,s.enabled,s.last_sync_at,s.last_sync_status,s.created_at,s.updated_at,COALESCE(s.sui_flavor,''), COALESCE((SELECT COUNT(*) FROM nodes WHERE source_id=s.id),0) as node_count FROM sources s ORDER BY s.id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var x Source
		var en int
		var l sql.NullString
		if err := rows.Scan(&x.ID, &x.Name, &x.Type, &x.PanelURL, &x.PanelToken, &en, &l, &x.LastSyncStatus, &x.CreatedAt, &x.UpdatedAt, &x.SUIFlavor, &x.NodeCount); err != nil {
			return nil, err
		}
		x.Enabled = en == 1
		if x.SUIFlavor == "" && x.Type == "sui_api" {
			x.SUIFlavor = "unknown"
		}
		if l.Valid {
			v := l.String
			x.LastSyncAt = &v
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Service) detectSuiFlavor(src Source) string {
	if src.Type != "sui_api" || strings.TrimSpace(src.PanelURL) == "" {
		return ""
	}
	base := strings.TrimRight(src.PanelURL, "/")
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/auth/me", nil)
	if err != nil {
		return "unknown"
	}
	if src.PanelToken != "" {
		req.Header.Set("x-panel-token", src.PanelToken)
		req.Header.Set("Authorization", "Bearer "+src.PanelToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var j map[string]any
	_ = json.Unmarshal(b, &j)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && fmt.Sprint(j["success"]) == "true" && (j["user"] != nil || j["panelPath"] != nil) {
		return "go"
	}
	return "node"
}

func (s *Service) Get(id int64) (Source, error) {
	var x Source
	var en int
	var l sql.NullString
	err := s.db.QueryRow(`SELECT id,name,source_type,panel_url,panel_token,enabled,last_sync_at,last_sync_status,created_at,updated_at,COALESCE(sui_flavor,''), COALESCE((SELECT COUNT(*) FROM nodes WHERE source_id=sources.id),0) as node_count FROM sources WHERE id=?`, id).Scan(&x.ID, &x.Name, &x.Type, &x.PanelURL, &x.PanelToken, &en, &l, &x.LastSyncStatus, &x.CreatedAt, &x.UpdatedAt, &x.SUIFlavor, &x.NodeCount)
	x.Enabled = en == 1
	if x.SUIFlavor == "" && x.Type == "sui_api" {
		x.SUIFlavor = "unknown"
	}
	if l.Valid {
		v := l.String
		x.LastSyncAt = &v
	}
	return x, err
}
func (s *Service) ExchangeCredentialToken(typ, panelURL, token string) (string, error) {
	typ = strings.TrimSpace(typ)
	token = strings.TrimSpace(token)
	if !isUserPassToken(token) {
		return token, nil
	}
	base := strings.TrimRight(panelURL, "/")
	if err := AssertURLSafe(base); err != nil {
		return "", err
	}
	switch typ {
	case "sui_api":
		return s.suiPermanentToken(base, token)
	case "sbui":
		return s.sbuiLogin(base, token)
	default:
		return token, nil
	}
}

func (s *Service) Create(name, typ, panelURL, token string) (Source, error) {
	typ = strings.TrimSpace(typ)
	if typ == "" {
		typ = "cf_sub"
	}
	if typ == "local" {
		return Source{}, errors.New("local source is managed by system")
	}
	var err error
	token, err = s.ExchangeCredentialToken(typ, panelURL, token)
	if err != nil {
		return Source{}, err
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
	src, err := s.Get(id)
	if err != nil {
		return err
	}
	token, err = s.ExchangeCredentialToken(src.Type, panelURL, token)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE sources SET name=?,panel_url=?,panel_token=?,enabled=?,updated_at=? WHERE id=? AND source_type!='local'`, name, panelURL, token, boolInt(enabled), time.Now().UTC().Format(time.RFC3339), id)
	return err
}
func (s *Service) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sources WHERE id=? AND source_type!='local'`, id)
	return err
}
func (s *Service) SyncAll() map[int64]string {
	rows, err := s.db.Query(`SELECT id FROM sources WHERE source_type!='local' AND enabled=1 ORDER BY id`)
	if err != nil {
		return map[int64]string{-1: err.Error()}
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return map[int64]string{-1: err.Error()}
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return map[int64]string{-1: err.Error()}
	}
	if err := rows.Close(); err != nil {
		return map[int64]string{-1: err.Error()}
	}
	out := map[int64]string{}
	for _, id := range ids {
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
	} else {
		status = fmt.Sprintf("ok (%d nodes)", len(links))
	}
	flavor := src.SUIFlavor
	if src.Type == "sui_api" {
		f := s.detectSuiFlavor(src)
		if f == "go" || f == "node" {
			flavor = f
		} else if flavor == "" {
			flavor = "unknown"
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = s.db.Exec(`UPDATE sources SET last_sync_at=?,last_sync_status=?,sui_flavor=?,updated_at=? WHERE id=?`, now, status, flavor, now, id)
	if err != nil {
		return err
	}
	return s.upsertNodes(id, links)
}
func (s *Service) fetchLinks(src Source) ([]string, error) {
	switch src.Type {
	case "cf_sub", "raw_sub":
		return s.fetchSubURL(src.PanelURL, src.PanelToken)
	case "sbui":
		return s.fetchSbuiLinks(src)
	case "sui_api":
		return s.fetchSuiLinks(src)
	default:
		return nil, fmt.Errorf("unsupported source type %s", src.Type)
	}
}
func (s *Service) fetchSuiLinks(src Source) ([]string, error) {
	inb, err := s.SuiJSON(src, "/api/inbounds", "GET", nil)
	if err == nil {
		if ok, _ := inb["success"].(bool); ok {
			if arr, ok := inb["obj"].([]any); ok {
				if len(arr) == 0 {
					return []string{}, nil
				}
				var links []string
				var linkErrs int
				for _, one := range arr {
					m, _ := one.(map[string]any)
					id := fmt.Sprint(m["id"])
					if id == "" || id == "<nil>" {
						continue
					}
					lj, er := s.SuiJSON(src, "/api/inbounds/"+id+"/links", "GET", nil)
					if er != nil {
						linkErrs++
						continue
					}
					if a, ok := lj["obj"].([]any); ok {
						for _, v := range a {
							if str := strings.TrimSpace(fmt.Sprint(v)); strings.Contains(str, "://") {
								links = append(links, str)
							}
						}
					}
				}
				if len(links) == 0 && linkErrs > 0 {
					return nil, fmt.Errorf("SUI inbounds found but links fetch failed")
				}
				return subconv.ParseSubscriptionText(strings.Join(links, "\n")), nil
			}
		}
	}
	return s.fetchSubURL(src.PanelURL, src.PanelToken)
}
func (s *Service) fetchSbuiLinks(src Source) ([]string, error) {
	u := src.PanelURL
	if !strings.Contains(u, "/api/v1/sub/") {
		u = strings.TrimRight(u, "/") + "/api/v1/sub/default"
	}
	token := src.PanelToken
	if isUserPassToken(token) {
		// SBUI default subscription is public; credentials are for management APIs.
		token = ""
	}
	return s.fetchSubURL(u, token)
}
func (s *Service) fetchSubURL(raw, token string) ([]string, error) {
	if err := AssertURLSafe(raw); err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", raw, nil)
	req.Header.Set("User-Agent", "subgo/0.4")
	req.Header.Set("Accept", "text/plain,*/*")
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
	seen := make(map[string]struct{})
	for _, raw := range links {
		// Skip non-link garbage (HTML/JS/etc)
		if !strings.Contains(raw, "://") || len(raw) > 2000 {
			continue
		}
		p := subconv.ParseRawLink(raw)
		h := subconv.StableHash(raw)
		seen[h] = struct{}{}
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
	rows, err := tx.Query(`SELECT id,node_hash FROM nodes WHERE source_id=?`, sourceID)
	if err != nil {
		return err
	}
	type staleNode struct {
		id   int64
		hash string
	}
	var stale []staleNode
	for rows.Next() {
		var id int64
		var h string
		if err := rows.Scan(&id, &h); err != nil {
			rows.Close()
			return err
		}
		if _, ok := seen[h]; !ok {
			stale = append(stale, staleNode{id: id, hash: h})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, n := range stale {
		if _, err := tx.Exec(`DELETE FROM nodes WHERE id=? AND source_id=?`, n.id, sourceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Service) Inbounds(sourceID int64) ([]Inbound, error) {
	src, err := s.Get(sourceID)
	if err != nil {
		return nil, err
	}
	switch src.Type {
	case "sbui":
		j, err := s.SbuiJSON(src, "/api/v1/inbounds", "GET", nil)
		if err != nil {
			return nil, err
		}
		return normalizeInboundArray(firstArray(j, "obj", "inbounds")), nil
	case "sui_api":
		j, err := s.SuiJSON(src, "/api/inbounds", "GET", nil)
		if err != nil {
			return nil, err
		}
		return normalizeInboundArray(firstArray(j, "obj", "inbounds")), nil
	default:
		return nil, errors.New("only sui_api/sbui source supports inbounds")
	}
}
func (s *Service) RealityQuick(sourceID int64, remark string) (map[string]any, error) {
	src, err := s.Get(sourceID)
	if err != nil {
		return nil, err
	}
	if remark == "" {
		remark = fmt.Sprintf("quick-%d", time.Now().Unix())
	}
	if src.Type == "sbui" {
		return s.SbuiJSON(src, "/api/v1/quick/reality", "POST", map[string]any{"remark": remark})
	}
	if src.Type == "sui_api" {
		return s.SuiJSON(src, "/api/inbounds/add-reality-quick", "POST", map[string]any{"remark": remark})
	}
	return nil, errors.New("only sui_api/sbui source supports reality quick")
}
func (s *Service) RenameInbound(sourceID, inboundID int64, remark string) error {
	src, err := s.Get(sourceID)
	if err != nil {
		return err
	}
	if remark == "" {
		return errors.New("remark required")
	}
	if src.Type == "sbui" {
		_, err = s.SbuiJSON(src, fmt.Sprintf("/api/v1/inbounds/%d/rename", inboundID), "PUT", map[string]any{"remark": remark})
		return err
	}
	if src.Type == "sui_api" {
		_, err = s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d", inboundID), "PUT", map[string]any{"remark": remark})
		return err
	}
	return errors.New("only sui_api/sbui source supports rename")
}
func (s *Service) DeleteInbound(sourceID, inboundID int64) error {
	src, err := s.Get(sourceID)
	if err != nil {
		return err
	}
	if src.Type == "sbui" {
		_, err = s.SbuiJSON(src, fmt.Sprintf("/api/v1/inbounds/%d", inboundID), "DELETE", nil)
		return err
	}
	if src.Type == "sui_api" {
		_, err = s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d", inboundID), "DELETE", nil)
		return err
	}
	return errors.New("only sui_api/sbui source supports delete")
}
func (s *Service) SuiJSON(src Source, path, method string, body any) (map[string]any, error) {
	base := strings.TrimRight(src.PanelURL, "/")
	if err := AssertURLSafe(base); err != nil {
		return nil, err
	}
	token := src.PanelToken
	if isUserPassToken(token) {
		var err error
		token, err = s.suiPermanentToken(base, token)
		if err != nil {
			return nil, err
		}
		_, _ = s.db.Exec(`UPDATE sources SET panel_token=?,updated_at=? WHERE id=?`, token, time.Now().UTC().Format(time.RFC3339), src.ID)
	}
	h := map[string]string{"x-panel-token": token, "authorization": "Bearer " + token, "content-type": "application/json", "accept": "application/json"}
	return s.SignedJSONRequest(base, path, method, h, body, token)
}
func (s *Service) SbuiJSON(src Source, path, method string, body any) (map[string]any, error) {
	base := normalizeSbuiBase(src.PanelURL)
	if err := AssertURLSafe(base); err != nil {
		return nil, err
	}
	token := src.PanelToken
	if isUserPassToken(token) {
		var err error
		token, err = s.sbuiLogin(base, token)
		if err != nil {
			return nil, err
		}
		_, _ = s.db.Exec(`UPDATE sources SET panel_token=?,updated_at=? WHERE id=?`, token, time.Now().UTC().Format(time.RFC3339), src.ID)
	}
	h := map[string]string{"accept": "application/json", "user-agent": "subgo/0.4"}
	if token != "" {
		h["authorization"] = "Bearer " + token
	}
	if body != nil {
		h["content-type"] = "application/json"
	}
	return s.SignedJSONRequest(base, path, method, h, body, token)
}

func (s *Service) suiPermanentToken(base, userPass string) (string, error) {
	parts := strings.SplitN(userPass, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "", errors.New("invalid SUI-Go credential, expected username:password")
	}
	j, err := s.JSONRequest(strings.TrimRight(base, "/")+"/auth/api-token", "POST", map[string]string{"content-type": "application/json", "accept": "application/json", "user-agent": "subgo/0.4"}, map[string]any{"username": strings.TrimSpace(parts[0]), "password": parts[1]})
	if err != nil {
		// Backward-compatible fallback for old SUI-Go builds; token may be a session token there.
		j, err = s.JSONRequest(strings.TrimRight(base, "/")+"/auth/login", "POST", map[string]string{"content-type": "application/json", "accept": "application/json", "user-agent": "subgo/0.4"}, map[string]any{"username": strings.TrimSpace(parts[0]), "password": parts[1]})
		if err != nil {
			return "", err
		}
	}
	token := strings.TrimSpace(fmt.Sprint(firstVal(j, "token", "access_token")))
	if token == "" || token == "<nil>" {
		return "", errors.New("SUI-Go token API did not return token")
	}
	return token, nil
}

func isUserPassToken(token string) bool {
	return strings.Contains(token, ":") && !strings.Contains(token, ".")
}

func (s *Service) sbuiLogin(base, userPass string) (string, error) {
	parts := strings.SplitN(userPass, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "", errors.New("invalid SBUI credential, expected username:password")
	}
	j, err := s.JSONRequest(strings.TrimRight(base, "/")+"/api/v1/login", "POST", map[string]string{"content-type": "application/json", "accept": "application/json", "user-agent": "subgo/0.4"}, map[string]any{"username": strings.TrimSpace(parts[0]), "password": parts[1]})
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(fmt.Sprint(firstVal(j, "token", "access_token")))
	if token == "" || token == "<nil>" {
		return "", errors.New("SBUI login did not return token")
	}
	return token, nil
}
func bodyBytes(body any) []byte {
	if body == nil {
		return nil
	}
	b, _ := json.Marshal(body)
	return b
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func tokenID(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])[:16]
}

func signPayload(token, method, path, bodyHash, nonce, ts string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(strings.ToUpper(method) + "\n" + path + "\n" + bodyHash + "\n" + nonce + "\n" + ts))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) challenge(base string) (string, string, error) {
	for _, p := range []string{"/auth/challenge", "/api/v1/auth/challenge"} {
		j, err := s.JSONRequest(strings.TrimRight(base, "/")+p, "GET", map[string]string{"accept": "application/json", "user-agent": "subgo/0.4"}, nil)
		if err == nil {
			nonce := strings.TrimSpace(fmt.Sprint(firstVal(j, "nonce")))
			ts := strings.TrimSpace(fmt.Sprint(firstVal(j, "timestamp")))
			if nonce != "" && nonce != "<nil>" && ts != "" && ts != "<nil>" {
				return nonce, ts, nil
			}
		}
	}
	return "", "", errors.New("handshake challenge unsupported")
}

func (s *Service) SignedJSONRequest(base, path, method string, headers map[string]string, body any, token string) (map[string]any, error) {
	bb := bodyBytes(body)
	bodyHash := sha256Hex(bb)
	if strings.TrimSpace(token) != "" {
		if nonce, ts, err := s.challenge(base); err == nil {
			h := map[string]string{"accept": "application/json", "content-type": "application/json", "user-agent": "subgo/0.4"}
			for k, v := range headers {
				if strings.ToLower(k) != "authorization" && strings.ToLower(k) != "x-panel-token" {
					h[k] = v
				}
			}
			h["x-panel-token-id"] = tokenID(token)
			h["x-panel-nonce"] = nonce
			h["x-panel-timestamp"] = ts
			h["x-panel-body-sha256"] = bodyHash
			h["x-panel-signature"] = signPayload(token, method, path, bodyHash, nonce, ts)
			if j, err := s.JSONRequestWithBytes(strings.TrimRight(base, "/")+path, method, h, bb); err == nil {
				return j, nil
			}
		}
	}
	return s.JSONRequestWithBytes(strings.TrimRight(base, "/")+path, method, headers, bb)
}

func (s *Service) JSONRequestWithBytes(raw, method string, headers map[string]string, bb []byte) (map[string]any, error) {
	if err := AssertURLSafe(raw); err != nil {
		return nil, err
	}
	var br io.Reader
	if bb != nil {
		br = bytes.NewReader(bb)
	}
	req, _ := http.NewRequest(method, raw, br)
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var j map[string]any
	_ = json.Unmarshal(text, &j)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return j, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if j == nil {
		return map[string]any{}, nil
	}
	return j, nil
}

func (s *Service) JSONRequest(raw, method string, headers map[string]string, body any) (map[string]any, error) {
	return s.JSONRequestWithBytes(raw, method, headers, bodyBytes(body))
}
func normalizeSbuiBase(raw string) string {
	base := strings.TrimRight(raw, "/")
	if strings.Contains(base, "/api/v1/sub/") {
		if u, err := url.Parse(base); err == nil {
			return u.Scheme + "://" + u.Host
		}
	}
	return base
}
func firstArray(j map[string]any, keys ...string) []any {
	for _, k := range keys {
		if a, ok := j[k].([]any); ok {
			return a
		}
	}
	return nil
}
func normalizeInboundArray(arr []any) []Inbound {
	out := []Inbound{}
	for _, v := range arr {
		m, _ := v.(map[string]any)
		id := toInt64(m["id"])
		proto := fmt.Sprint(firstVal(m, "protocol", "type"))
		out = append(out, Inbound{ID: id, DisplayID: fmt.Sprintf("%03d", id), Remark: fmt.Sprint(firstVal(m, "remark", "tag", "node_name")), Protocol: proto, Port: firstVal(m, "port", "listen_port"), Enable: fmt.Sprint(firstVal(m, "enable", "enabled")) != "false", Raw: m})
	}
	return out
}
func firstVal(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	return ""
}
func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		i, _ := strconv.ParseInt(x, 10, 64)
		return i
	}
	return 0
}

func AssertURLSafe(raw string) error {
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
func GzipDecode(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
