package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
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
	case "xui", "3x_ui":
		// 3x-ui does not expose a permanent token from username/password; keep
		// credentials encrypted-at-rest by the host and log in per sync/API call.
		return token, nil
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
	case "xui", "3x_ui":
		return s.fetch3XUILinks(src)
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
func (s *Service) fetch3XUILinks(src Source) ([]string, error) {
	allSettings := map[string]any{}
	if j, err := s.XUIJSON(src, "/panel/setting/all", "POST", nil); err == nil {
		if m, ok := j["obj"].(map[string]any); ok {
			allSettings = m
		}
	}
	defaultSettings := map[string]any{}
	if j, err := s.XUIJSON(src, "/panel/setting/defaultSettings", "POST", nil); err == nil {
		if m, ok := j["obj"].(map[string]any); ok {
			defaultSettings = m
		}
	}
	baseSubURLs := xuiSubscriptionBases(src.PanelURL, allSettings, defaultSettings)
	j, err := s.XUIJSON(src, "/panel/api/inbounds/list", "GET", nil)
	if err != nil {
		return nil, err
	}
	arr := firstArray(j, "obj", "inbounds")
	if len(arr) == 0 {
		return []string{}, nil
	}
	seenSubID := map[string]struct{}{}
	links := []string{}
	fetchErrs := 0
	for _, one := range arr {
		m, _ := one.(map[string]any)
		for _, sid := range xuiSubIDsFromInbound(m) {
			if _, ok := seenSubID[sid]; ok {
				continue
			}
			seenSubID[sid] = struct{}{}
			var lastErr error
			for _, baseSubURL := range baseSubURLs {
				subURL := strings.TrimRight(baseSubURL, "/") + "/" + url.PathEscape(sid)
				subLinks, err := s.fetchSubURL(subURL, "")
				if err != nil {
					lastErr = err
					continue
				}
				links = append(links, subLinks...)
				lastErr = nil
				break
			}
			if lastErr != nil {
				fetchErrs++
			}
		}
	}
	if len(links) == 0 && fetchErrs > 0 {
		return nil, fmt.Errorf("3x-ui clients found but subscription fetch failed")
	}
	return links, nil
}

func xuiSubscriptionBases(panelURL string, allSettings, defaultSettings map[string]any) []string {
	out := []string{}
	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimRight(strings.TrimSpace(v), "/")
		if v == "" || v == "<nil>" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	path := strings.TrimSpace(fmt.Sprint(firstVal(allSettings, "subPath", "SubPath")))
	if path == "" || path == "<nil>" {
		path = strings.TrimSpace(fmt.Sprint(firstVal(defaultSettings, "subPath", "SubPath")))
	}
	if path == "" || path == "<nil>" {
		path = "/sub/"
	}
	// Prefer explicitly configured reverse proxy URI, then the panel origin plus
	// subPath. The latter is the common Nginx/Cloudflare deployment shape.
	for _, k := range []string{"subURI", "SubURI"} {
		add(fmt.Sprint(allSettings[k]))
	}
	if u, err := url.Parse(strings.TrimRight(panelURL, "/")); err == nil {
		u.Path, u.RawQuery, u.Fragment = "", "", ""
		add(strings.TrimRight(u.String(), "/") + "/" + strings.Trim(path, "/"))
	}
	// 3x-ui defaultSettings may include its own direct subscription-port URL;
	// keep it as fallback for non-reverse-proxied installs.
	for _, k := range []string{"subURI", "SubURI"} {
		add(fmt.Sprint(defaultSettings[k]))
	}
	if len(out) == 0 {
		add(strings.TrimRight(panelURL, "/") + "/" + strings.Trim(path, "/"))
	}
	return out
}

func xuiSubIDsFromInbound(inb map[string]any) []string {
	out := []string{}
	seen := map[string]struct{}{}
	add := func(v any) {
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" || s == "<nil>" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	var settings map[string]any
	switch v := inb["settings"].(type) {
	case string:
		_ = json.Unmarshal([]byte(v), &settings)
	case map[string]any:
		settings = v
	}
	if settings != nil {
		if arr, ok := settings["clients"].([]any); ok {
			for _, one := range arr {
				c, _ := one.(map[string]any)
				add(c["subId"])
			}
		}
	}
	return out
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
		// Skip non-link garbage (HTML/JS/etc). 3x-ui Reality/ML-DSA links can be
		// very long because mldsa65Verify is embedded in the URL, so keep the
		// guard high enough for legitimate proxy links.
		if !strings.Contains(raw, "://") || len(raw) > 20000 {
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
	case "xui", "3x_ui":
		j, err := s.XUIJSON(src, "/panel/api/inbounds/list", "GET", nil)
		if err != nil {
			return nil, err
		}
		return normalizeXUIClientArray(firstArray(j, "obj", "inbounds")), nil
	default:
		return nil, errors.New("only sui_api/sbui/3x-ui source supports inbounds")
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
	if src.Type == "xui" || src.Type == "3x_ui" {
		return s.xuiRealityQuick(src, remark)
	}
	return nil, errors.New("only sui_api/sbui/3x-ui source supports reality quick")
}

func (s *Service) xuiRealityQuick(src Source, remark string) (map[string]any, error) {
	port := int64(20000)
	if arr, err := s.Inbounds(src.ID); err == nil {
		used := map[int64]struct{}{}
		maxPort := int64(19999)
		for _, inb := range arr {
			p := toInt64(inb.Port)
			if p > 0 {
				used[p] = struct{}{}
				if p > maxPort {
					maxPort = p
				}
			}
		}
		for p := maxPort + 1; p < maxPort+2000; p++ {
			if p < 20000 {
				continue
			}
			if _, ok := used[p]; !ok {
				port = p
				break
			}
		}
	}
	uuid, err := randomUUID()
	if err != nil {
		return nil, err
	}
	priv, pub, err := xrayX25519()
	if err != nil {
		return nil, err
	}
	subID, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	emailSeed, err := randomToken(6)
	if err != nil {
		return nil, err
	}
	email := safeXUIClientEmail(remark)
	if email == "" {
		email = "u" + emailSeed
	}
	shortID, err := randomHex(4)
	if err != nil {
		return nil, err
	}
	settings, _ := json.Marshal(map[string]any{
		"clients":    []map[string]any{{"id": uuid, "flow": "", "email": email, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": true, "tgId": "", "subId": subID, "reset": 0}},
		"decryption": "none", "encryption": "none",
	})
	stream, _ := json.Marshal(map[string]any{
		"network": "tcp", "security": "reality", "externalProxy": []any{},
		"realitySettings": map[string]any{
			"show": false, "xver": 0, "target": "www.amazon.com:443", "serverNames": []string{"www.amazon.com", "amazon.com"}, "privateKey": priv,
			"minClientVer": "", "maxClientVer": "", "maxTimediff": 0, "shortIds": []string{shortID},
			"settings": map[string]any{"publicKey": pub, "fingerprint": "chrome", "serverName": "", "spiderX": "/"},
		},
		"tcpSettings": map[string]any{"acceptProxyProtocol": false, "header": map[string]any{"type": "none"}},
	})
	sniffing, _ := json.Marshal(map[string]any{"enabled": false, "destOverride": []string{"http", "tls", "quic", "fakedns"}, "metadataOnly": false, "routeOnly": false})
	payload := map[string]any{"up": 0, "down": 0, "total": 0, "remark": remark, "enable": true, "expiryTime": 0, "listen": "", "port": port, "protocol": "vless", "settings": string(settings), "streamSettings": string(stream), "sniffing": string(sniffing)}
	return s.XUIJSON(src, "/panel/api/inbounds/add", "POST", payload)
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func randomToken(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

func randomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func xrayX25519() (string, string, error) {
	out, err := exec.Command("xray", "x25519").Output()
	if err != nil {
		return "", "", err
	}
	priv, pub := "", ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey:") {
			priv = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		}
		if strings.HasPrefix(line, "Password (PublicKey):") {
			pub = strings.TrimSpace(strings.TrimPrefix(line, "Password (PublicKey):"))
		}
	}
	if priv == "" || pub == "" {
		return "", "", errors.New("xray x25519 did not return keys")
	}
	return priv, pub, nil
}
func (s *Service) RenameNodeByRaw(sourceID int64, rawLink, remark string) error {
	rawLink = strings.TrimSpace(rawLink)
	if rawLink == "" {
		return errors.New("raw link required")
	}
	src, err := s.Get(sourceID)
	if err != nil {
		return err
	}
	targetHash := subconv.StableHash(rawLink)
	switch src.Type {
	case "sui_api":
		j, err := s.SuiJSON(src, "/api/inbounds", "GET", nil)
		if err != nil {
			return err
		}
		for _, one := range firstArray(j, "obj", "inbounds") {
			m, _ := one.(map[string]any)
			id := toInt64(m["id"])
			if id <= 0 {
				continue
			}
			lj, er := s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d/links", id), "GET", nil)
			if er != nil {
				continue
			}
			if a, ok := lj["obj"].([]any); ok {
				for _, v := range a {
					candidate := strings.TrimSpace(fmt.Sprint(v))
					if candidate != "" && subconv.StableHash(candidate) == targetHash {
						return s.RenameInbound(sourceID, id, remark)
					}
				}
			}
		}
		return errors.New("upstream inbound not found for node link")
	case "sbui", "xui", "3x_ui":
		return errors.New("rename by raw link is not supported for this source type")
	default:
		return errors.New("source type does not support upstream rename")
	}
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
		payload := map[string]any{"remark": remark}
		if cur, er := s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d/full", inboundID), "GET", nil); er == nil {
			if obj, ok := cur["obj"].(map[string]any); ok {
				payload = obj
				payload["remark"] = remark
			}
		} else if cur, er := s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d", inboundID), "GET", nil); er == nil {
			if obj, ok := cur["obj"].(map[string]any); ok {
				payload = obj
				payload["remark"] = remark
			}
		}
		_, err = s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d/full", inboundID), "PUT", payload)
		if err != nil {
			_, err = s.SuiJSON(src, fmt.Sprintf("/api/inbounds/%d", inboundID), "PUT", payload)
		}
		return err
	}
	if src.Type == "xui" || src.Type == "3x_ui" {
		return s.xuiRenameClient(src, inboundID, remark)
	}
	return errors.New("only sui_api/sbui/3x-ui source supports rename")
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
	if src.Type == "xui" || src.Type == "3x_ui" {
		return s.xuiDeleteClient(src, inboundID)
	}
	return errors.New("only sui_api/sbui/3x-ui source supports delete")
}

func (s *Service) xuiRenameClient(src Source, clientID int64, remark string) error {
	inb, client, clientKey, err := s.xuiFindClient(src, clientID)
	if err != nil {
		return err
	}
	client["email"] = remark
	settings, _ := json.Marshal(map[string]any{"clients": []map[string]any{client}})
	_, err = s.XUIJSON(src, fmt.Sprintf("/panel/api/inbounds/updateClient/%s", url.PathEscape(clientKey)), "POST", map[string]any{"id": toInt64(inb["id"]), "settings": string(settings)})
	return err
}

func (s *Service) xuiDeleteClient(src Source, clientID int64) error {
	inb, _, clientKey, err := s.xuiFindClient(src, clientID)
	if err != nil {
		return err
	}
	j, err := s.XUIJSON(src, fmt.Sprintf("/panel/api/inbounds/%d/delClient/%s", toInt64(inb["id"]), url.PathEscape(clientKey)), "POST", nil)
	if err != nil {
		return err
	}
	if ok, has := j["success"].(bool); has && !ok {
		msg := strings.TrimSpace(fmt.Sprint(j["msg"]))
		if strings.Contains(strings.ToLower(msg), "no client remained") {
			del, er := s.XUIJSON(src, fmt.Sprintf("/panel/api/inbounds/del/%d", toInt64(inb["id"])), "POST", nil)
			if er != nil {
				return er
			}
			if ok, has := del["success"].(bool); has && !ok {
				return errors.New(strings.TrimSpace(fmt.Sprint(del["msg"])))
			}
			return nil
		}
		if msg == "" {
			msg = "3x-ui client delete failed"
		}
		return errors.New(msg)
	}
	return nil
}

func safeXUIClientEmail(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	return strings.Trim(out, ".-_")
}

func (s *Service) xuiFindClient(src Source, clientID int64) (map[string]any, map[string]any, string, error) {
	j, err := s.XUIJSON(src, "/panel/api/inbounds/list", "GET", nil)
	if err != nil {
		return nil, nil, "", err
	}
	for _, one := range firstArray(j, "obj", "inbounds") {
		inb, _ := one.(map[string]any)
		settings := map[string]any{}
		switch v := inb["settings"].(type) {
		case string:
			_ = json.Unmarshal([]byte(v), &settings)
		case map[string]any:
			settings = v
		}
		clients, _ := settings["clients"].([]any)
		stats := xuiClientStats(inb)
		for idx, oneClient := range clients {
			client, _ := oneClient.(map[string]any)
			if client == nil {
				continue
			}
			statID := xuiClientStatID(client, stats)
			if statID != clientID && toInt64(client["_subgo_client_id"]) != clientID {
				if generated := xuiSyntheticClientID(inb, client, idx); generated != clientID {
					continue
				}
			}
			key := xuiClientKey(strings.TrimSpace(fmt.Sprint(inb["protocol"])), client)
			if key == "" {
				return nil, nil, "", errors.New("3x-ui client key is empty")
			}
			return inb, client, key, nil
		}
	}
	return nil, nil, "", errors.New("3x-ui client not found")
}

func xuiClientKey(protocol string, client map[string]any) string {
	switch strings.ToLower(protocol) {
	case "trojan":
		return strings.TrimSpace(fmt.Sprint(client["password"]))
	case "shadowsocks":
		return strings.TrimSpace(fmt.Sprint(firstVal(client, "email", "id", "password")))
	default:
		return strings.TrimSpace(fmt.Sprint(client["id"]))
	}
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

func (s *Service) XUIJSON(src Source, path, method string, body any) (map[string]any, error) {
	base := strings.TrimRight(src.PanelURL, "/")
	if err := AssertURLSafe(base); err != nil {
		return nil, err
	}
	apiBase := s.resolveXUIBase(base)
	headers := map[string]string{"accept": "application/json", "user-agent": "subgo/0.4", "x-requested-with": "XMLHttpRequest"}
	if body != nil {
		headers["content-type"] = "application/json"
	}
	if tok := strings.TrimSpace(src.PanelToken); tok != "" && !isUserPassToken(tok) {
		headers["authorization"] = "Bearer " + tok
		return s.JSONRequestWithBytes(apiBase+path, method, headers, bodyBytes(body))
	}
	client, csrf, err := s.xuiLoginClient(apiBase, src.PanelToken)
	if err != nil {
		return nil, err
	}
	if csrf != "" && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		headers["x-csrf-token"] = csrf
	}
	return s.JSONRequestWithClient(client, apiBase+path, method, headers, bodyBytes(body))
}

func (s *Service) resolveXUIBase(base string) string {
	base = xuiPanelAPIBase(base)
	u, err := url.Parse(base)
	if err != nil || strings.Trim(u.Path, "/") != "" {
		return base
	}
	// 3x-ui installations normally hide the panel behind a random webBasePath.
	// If the user enters only the origin (https://host), discover that path from
	// the root redirect and use it for all panel API/login requests.
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", strings.TrimRight(base, "/")+"/", nil)
	if err != nil {
		return base
	}
	req.Header.Set("User-Agent", "subgo/0.4")
	resp, err := client.Do(req)
	if err != nil {
		return base
	}
	defer resp.Body.Close()
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if loc == "" || (resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect) {
		return base
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return base
	}
	if lu.IsAbs() {
		if lu.Scheme != u.Scheme || lu.Host != u.Host {
			return base
		}
		u.Path = lu.Path
	} else if strings.HasPrefix(loc, "/") {
		u.Path = lu.Path
	}
	u.RawQuery, u.Fragment = "", ""
	if strings.Trim(u.Path, "/") == "" {
		return base
	}
	return strings.TrimRight(u.String(), "/")
}

func xuiPanelAPIBase(base string) string {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return strings.TrimRight(base, "/")
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	if strings.HasSuffix(path, "/panel") {
		u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/panel")
	}
	return strings.TrimRight(u.String(), "/")
}

func (s *Service) xuiLoginClient(base, userPass string) (*http.Client, string, error) {
	parts := strings.SplitN(userPass, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return nil, "", errors.New("invalid 3x-ui credential, expected username:password or API token")
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: s.client.Timeout, Jar: jar}
	csrf := ""
	if j, err := s.JSONRequestWithClient(client, strings.TrimRight(base, "/")+"/csrf-token", "GET", map[string]string{"accept": "application/json", "x-requested-with": "XMLHttpRequest", "user-agent": "subgo/0.4"}, nil); err == nil {
		csrf = strings.TrimSpace(fmt.Sprint(firstVal(j, "obj", "token")))
	}
	form := url.Values{}
	form.Set("username", strings.TrimSpace(parts[0]))
	form.Set("password", parts[1])
	headers := map[string]string{"content-type": "application/x-www-form-urlencoded; charset=UTF-8", "accept": "application/json", "x-requested-with": "XMLHttpRequest", "user-agent": "subgo/0.4"}
	if csrf != "" {
		headers["x-csrf-token"] = csrf
	}
	j, err := s.JSONRequestWithClient(client, strings.TrimRight(base, "/")+"/login", "POST", headers, []byte(form.Encode()))
	if err != nil {
		return nil, "", err
	}
	if ok, _ := j["success"].(bool); !ok {
		return nil, "", fmt.Errorf("3x-ui login failed: %s", strings.TrimSpace(fmt.Sprint(j["msg"])))
	}
	if csrf == "" {
		if j, err := s.JSONRequestWithClient(client, strings.TrimRight(base, "/")+"/panel/csrf-token", "GET", map[string]string{"accept": "application/json", "x-requested-with": "XMLHttpRequest", "user-agent": "subgo/0.4"}, nil); err == nil {
			csrf = strings.TrimSpace(fmt.Sprint(firstVal(j, "obj", "token")))
		}
	}
	return client, csrf, nil
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

func (s *Service) JSONRequestWithClient(client *http.Client, raw, method string, headers map[string]string, bb []byte) (map[string]any, error) {
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
	resp, err := client.Do(req)
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

func normalizeXUIClientArray(arr []any) []Inbound {
	out := []Inbound{}
	for _, v := range arr {
		inb, _ := v.(map[string]any)
		if inb == nil {
			continue
		}
		inboundID := toInt64(inb["id"])
		proto := strings.TrimSpace(fmt.Sprint(firstVal(inb, "protocol", "type")))
		settings := map[string]any{}
		switch raw := inb["settings"].(type) {
		case string:
			_ = json.Unmarshal([]byte(raw), &settings)
		case map[string]any:
			settings = raw
		}
		clients, _ := settings["clients"].([]any)
		stats := xuiClientStats(inb)
		if len(clients) == 0 {
			out = append(out, Inbound{ID: inboundID, DisplayID: fmt.Sprintf("%03d", inboundID), Remark: fmt.Sprint(firstVal(inb, "remark", "tag", "node_name")), Protocol: proto, Port: firstVal(inb, "port", "listen_port"), Enable: fmt.Sprint(firstVal(inb, "enable", "enabled")) != "false", Raw: inb})
			continue
		}
		for idx, oneClient := range clients {
			client, _ := oneClient.(map[string]any)
			if client == nil {
				continue
			}
			cid := xuiClientStatID(client, stats)
			if cid <= 0 {
				cid = xuiSyntheticClientID(inb, client, idx)
			}
			enabled := fmt.Sprint(firstVal(inb, "enable", "enabled")) != "false" && fmt.Sprint(firstVal(client, "enable", "enabled")) != "false"
			remark := strings.TrimSpace(fmt.Sprint(firstVal(client, "email", "id", "password")))
			display := fmt.Sprintf("%03d/%s", inboundID, remark)
			if remark == "" {
				display = fmt.Sprintf("%03d/%03d", inboundID, cid)
			}
			out = append(out, Inbound{ID: cid, DisplayID: display, Remark: remark, Protocol: proto, Port: firstVal(inb, "port", "listen_port"), Enable: enabled, Raw: map[string]any{"inbound": inb, "client": client}})
		}
	}
	return out
}

func xuiClientStats(inb map[string]any) []map[string]any {
	out := []map[string]any{}
	arr, _ := inb["clientStats"].([]any)
	for _, one := range arr {
		m, _ := one.(map[string]any)
		if m != nil {
			out = append(out, m)
		}
	}
	return out
}

func xuiClientStatID(client map[string]any, stats []map[string]any) int64 {
	uuid := strings.TrimSpace(fmt.Sprint(client["id"]))
	email := strings.TrimSpace(fmt.Sprint(client["email"]))
	subID := strings.TrimSpace(fmt.Sprint(client["subId"]))
	for _, st := range stats {
		if uuid != "" && uuid == strings.TrimSpace(fmt.Sprint(st["uuid"])) {
			return toInt64(st["id"])
		}
		if email != "" && email == strings.TrimSpace(fmt.Sprint(st["email"])) {
			return toInt64(st["id"])
		}
		if subID != "" && subID == strings.TrimSpace(fmt.Sprint(st["subId"])) {
			return toInt64(st["id"])
		}
	}
	return 0
}

func xuiSyntheticClientID(inb, client map[string]any, idx int) int64 {
	seed := fmt.Sprintf("%v|%v|%v|%v", inb["id"], idx, client["id"], firstVal(client, "email", "password", "subId"))
	sum := sha256.Sum256([]byte(seed))
	v := int64(sum[0])<<24 | int64(sum[1])<<16 | int64(sum[2])<<8 | int64(sum[3])
	if v < 0 {
		v = -v
	}
	return 900000000 + (v % 100000000)
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
