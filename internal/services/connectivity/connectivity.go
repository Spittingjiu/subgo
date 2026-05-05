package connectivity

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/subconv"
	"gopkg.in/yaml.v3"
)

const KernelBin = "/usr/local/bin/sing-box"
const MihomoBin = "/usr/local/bin/mihomo"
const KernelTmp = "/opt/subgo/singbox-install"

type Service struct{ db *sql.DB }
type Result struct {
	NodeID    int64  `json:"node_id"`
	Status    string `json:"status"`
	LatencyMS *int64 `json:"latency_ms"`
	LastError string `json:"last_error"`
	CheckedAt string `json:"checked_at"`
}
type KernelStatus struct {
	OK        bool   `json:"ok"`
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	Kernel    string `json:"kernel"`
}

func New(db *sql.DB) *Service { return &Service{db: db} }
func (s *Service) EnsureSchema() {
	s.db.Exec(`CREATE TABLE IF NOT EXISTS node_connectivity (node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, status TEXT NOT NULL, latency_ms INTEGER, last_error TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL)`)
}
func (s *Service) KernelStatus() KernelStatus {
	st := KernelStatus{OK: true, Path: KernelBin, Mode: "sing-box+proxy", Kernel: "sing-box"}
	if _, err := os.Stat(KernelBin); err == nil {
		st.Installed = true
		out, _ := exec.Command(KernelBin, "version").CombinedOutput()
		st.Version = strings.TrimSpace(string(out))
	}
	return st
}
func (s *Service) InstallKernel() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("auto install currently supports linux")
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "amd64"
	} else if arch == "arm64" {
		arch = "arm64"
	} else {
		return "", fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
	req.Header.Set("User-Agent", "subgo")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch release HTTP %d", resp.StatusCode)
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	var assetURL string
	needle := "linux-" + arch
	for _, a := range rel.Assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, "sing-box") && strings.Contains(n, needle) && strings.HasSuffix(n, ".tar.gz") && !strings.Contains(n, "android") {
			assetURL = a.URL
			break
		}
	}
	if assetURL == "" {
		return "", fmt.Errorf("no sing-box %s tar.gz asset found", needle)
	}
	r, err := http.Get(assetURL)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return "", fmt.Errorf("download HTTP %d", r.StatusCode)
	}
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(KernelTmp, 0755); err != nil {
		return "", err
	}
	tmp := filepath.Join(KernelTmp, "sing-box.new")
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if filepath.Base(h.Name) != "sing-box" {
			continue
		}
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return "", err
		}
		f.Close()
		found = true
		break
	}
	if !found {
		return "", errors.New("sing-box binary not found in archive")
	}
	if err := os.Rename(tmp, KernelBin); err != nil {
		return "", err
	}
	_ = os.Chmod(KernelBin, 0755)
	out, err := exec.Command(KernelBin, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("verify failed: %s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
func (s *Service) UninstallKernel() error {
	if _, err := os.Stat(KernelBin); err == nil {
		return os.Remove(KernelBin)
	}
	return nil
}
func (s *Service) List() ([]Result, error) {
	s.EnsureSchema()
	rows, err := s.db.Query(`SELECT node_id,status,latency_ms,last_error,checked_at FROM node_connectivity ORDER BY checked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var r Result
		var lat sql.NullInt64
		if err := rows.Scan(&r.NodeID, &r.Status, &lat, &r.LastError, &r.CheckedAt); err != nil {
			return nil, err
		}
		if lat.Valid {
			r.LatencyMS = &lat.Int64
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Service) Check(limit int) ([]Result, error) {
	s.EnsureSchema()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id,raw_link FROM nodes WHERE enabled=1 ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type job struct {
		id  int64
		raw string
	}
	var jobs []job
	for rows.Next() {
		var j job
		_ = rows.Scan(&j.id, &j.raw)
		jobs = append(jobs, j)
	}
	var res []Result
	for _, j := range jobs {
		r := s.checkWithSingBox(j.id, j.raw)
		res = append(res, r)
		s.save(r)
	}
	return res, nil
}

func (s *Service) checkWithSingBox(id int64, raw string) Result {
	p := subconv.ParseRawLink(raw)
	now := time.Now().UTC().Format(time.RFC3339)
	if p.Host == "" || p.Port == 0 {
		return Result{NodeID: id, Status: "unknown", LastError: "missing host/port", CheckedAt: now}
	}
	if isXHTTPLink(raw) {
		if _, err := os.Stat(MihomoBin); err == nil {
			return s.checkWithMihomo(id, raw, now)
		}
	}
	if _, err := os.Stat(KernelBin); err != nil {
		return s.tcpCheck(id, raw, now)
	}

	dir, err := os.MkdirTemp("", "subgo-conn-")
	if err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: "temp dir failed", CheckedAt: now}
	}
	defer os.RemoveAll(dir)

	port := 31000 + int(time.Now().UnixNano())%(60999-31000)
	cfgPath := filepath.Join(dir, "config.json")
	cfg := s.buildSingBoxCheckConfig(raw, p, port)
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, cfgJSON, 0644); err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: "config write failed", CheckedAt: now}
	}

	// Validate config
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	checkCmd := exec.CommandContext(ctx, KernelBin, "check", "-c", cfgPath)
	if out, err2 := checkCmd.CombinedOutput(); err2 != nil {
		return Result{NodeID: id, Status: "unknown", LastError: fmt.Sprintf("config: %s", trimLine(string(out))), CheckedAt: now}
	}

	// Start sing-box
	runCtx, runCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer runCancel()
	cmd := exec.CommandContext(runCtx, KernelBin, "run", "-c", cfgPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: "sing-box start failed", CheckedAt: now}
	}
	defer func() { cmd.Process.Kill() }()

	// Wait for port
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 50; i++ {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return Result{NodeID: id, Status: "fail", LastError: "proxy port not ready", CheckedAt: now}
	}

	// Test through proxy
	start := time.Now()
	testCtx, testCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer testCancel()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", addr))
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	testReq, _ := http.NewRequestWithContext(testCtx, "GET", "https://www.gstatic.com/generate_204", nil)
	resp, err := client.Do(testReq)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Result{NodeID: id, Status: "fail", LastError: fmt.Sprintf("proxy: %s", trimStr(err.Error(), 160)), CheckedAt: now}
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return Result{NodeID: id, Status: "ok", LatencyMS: &lat, CheckedAt: now}
	}
	return Result{NodeID: id, Status: "fail", LastError: fmt.Sprintf("HTTP %d", resp.StatusCode), CheckedAt: now}
}

func (s *Service) checkWithMihomo(id int64, raw string, now string) Result {
	proxies := []map[string]any{subconv.ClashProxy(raw)}
	if len(proxies) == 0 || proxies[0] == nil {
		return Result{NodeID: id, Status: "unknown", LastError: "mihomo: unsupported or malformed proxy", CheckedAt: now}
	}
	name, _ := proxies[0]["name"].(string)
	if name == "" {
		name = fmt.Sprintf("node-%d", id)
		proxies[0]["name"] = name
	}
	dir, err := os.MkdirTemp("", "subgo-mihomo-")
	if err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: "mihomo temp dir failed", CheckedAt: now}
	}
	defer os.RemoveAll(dir)
	port := 32000 + int(time.Now().UnixNano())%(60999-32000)
	cfg := map[string]any{
		"mixed-port": port,
		"allow-lan":  false,
		"mode":       "global",
		"log-level":  "error",
		"proxies":    proxies,
		"proxy-groups": []map[string]any{
			{"name": "PROXY", "type": "select", "proxies": []string{name}},
		},
		"rules": []string{"MATCH,PROXY"},
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML, _ := yaml.Marshal(cfg)
	if err := os.WriteFile(cfgPath, cfgYAML, 0644); err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: "mihomo config write failed", CheckedAt: now}
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()
	if out, err := exec.CommandContext(checkCtx, MihomoBin, "-t", "-f", cfgPath).CombinedOutput(); err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: fmt.Sprintf("mihomo config: %s", trimLine(string(out))), CheckedAt: now}
	}
	runCtx, runCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer runCancel()
	cmd := exec.CommandContext(runCtx, MihomoBin, "-f", cfgPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return Result{NodeID: id, Status: "unknown", LastError: "mihomo start failed", CheckedAt: now}
	}
	defer func() { _ = cmd.Process.Kill() }()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 50; i++ {
		if conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return Result{NodeID: id, Status: "fail", LastError: "mihomo proxy port not ready", CheckedAt: now}
	}
	start := time.Now()
	testCtx, testCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer testCancel()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", addr))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 8 * time.Second}
	req, _ := http.NewRequestWithContext(testCtx, "GET", "https://www.gstatic.com/generate_204", nil)
	resp, err := client.Do(req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return Result{NodeID: id, Status: "fail", LastError: fmt.Sprintf("mihomo proxy: %s", trimStr(err.Error(), 160)), CheckedAt: now}
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return Result{NodeID: id, Status: "ok", LatencyMS: &lat, CheckedAt: now}
	}
	return Result{NodeID: id, Status: "fail", LastError: fmt.Sprintf("mihomo HTTP %d", resp.StatusCode), CheckedAt: now}
}

func (s *Service) tcpCheck(id int64, raw string, now string) Result {
	p := subconv.ParseRawLink(raw)
	if p.Host == "" || p.Port == 0 {
		return Result{NodeID: id, Status: "unknown", LastError: "missing host/port", CheckedAt: now}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), 4*time.Second)
	if err != nil {
		return Result{NodeID: id, Status: "fail", LastError: err.Error(), CheckedAt: now}
	}
	conn.Close()
	ms := time.Since(start).Milliseconds()
	return Result{NodeID: id, Status: "ok", LatencyMS: &ms, CheckedAt: now}
}

func (s *Service) save(r Result) {
	var lat any
	if r.LatencyMS != nil {
		lat = *r.LatencyMS
	}
	_, _ = s.db.Exec(`INSERT INTO node_connectivity(node_id,status,latency_ms,last_error,checked_at) VALUES(?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET status=excluded.status,latency_ms=excluded.latency_ms,last_error=excluded.last_error,checked_at=excluded.checked_at`, r.NodeID, r.Status, lat, r.LastError, r.CheckedAt)
}

func (s *Service) buildSingBoxCheckConfig(raw string, p subconv.ParsedLink, port int) map[string]any {
	outboundTag := fmt.Sprintf("check-%d", port)
	outbound := s.buildOutbound(raw, p, outboundTag)
	return map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []map[string]any{
			{"type": "http", "tag": "test-in", "listen": "127.0.0.1", "listen_port": port},
		},
		"outbounds": []map[string]any{
			outbound,
			{"type": "direct", "tag": "direct-out"},
		},
		"route": map[string]any{
			"rules": []map[string]any{
				{"inbound": "test-in", "outbound": outboundTag},
			},
		},
	}
}

func (s *Service) buildOutbound(raw string, p subconv.ParsedLink, tag string) map[string]any {
	host := p.Host
	port := p.Port
	proto := p.Protocol

	switch proto {
	case "vless":
		m := map[string]any{
			"type": "vless", "tag": tag, "server": host, "server_port": port,
			"uuid": extractUUID(raw), "tls": map[string]any{"enabled": true},
		}
		if u, err := url.Parse(raw); err == nil {
			q := u.Query()
			network := orStr(q.Get("type"), "tcp")
			sni := orStr(q.Get("sni"), q.Get("host"))
			m["network"] = network
			if sni != "" {
				m["tls"].(map[string]any)["server_name"] = sni
			}
			if flow := q.Get("flow"); flow != "" && network != "xhttp" {
				m["flow"] = flow
			}
			m["tls"].(map[string]any)["utls"] = map[string]any{
				"enabled": true, "fingerprint": orStr(q.Get("fp"), "chrome"),
			}
			if q.Get("security") == "reality" && q.Get("pbk") != "" {
				m["tls"].(map[string]any)["reality"] = map[string]any{
					"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid"),
				}
			}
			switch network {
			case "ws":
				m["transport"] = map[string]any{
					"type": "ws", "path": orStr(q.Get("path"), "/"),
					"headers": map[string]any{"Host": orStr(sni, host)},
				}
			case "xhttp":
				// sing-box uses tcp network + http transport for xhttp
				m["network"] = "tcp"
				m["transport"] = map[string]any{
					"type": "http",
					"host": []string{orStr(sni, host)},
					"path": orStr(q.Get("path"), "/"),
				}
			}
		}
		return m

	case "hysteria2", "hy2":
		m := map[string]any{
			"type": "hysteria2", "tag": tag, "server": host, "server_port": port,
			"password": extractPass(raw), "tls": map[string]any{"enabled": true},
		}
		if u, err := url.Parse(raw); err == nil {
			if sni := u.Query().Get("sni"); sni != "" {
				m["tls"].(map[string]any)["server_name"] = sni
			}
			if u.Query().Get("insecure") == "1" {
				m["tls"].(map[string]any)["insecure"] = true
			}
		}
		return m

	case "trojan":
		m := map[string]any{
			"type": "trojan", "tag": tag, "server": host, "server_port": port,
			"password": extractPass(raw), "tls": map[string]any{"enabled": true},
		}
		if u, err := url.Parse(raw); err == nil {
			if sni := u.Query().Get("sni"); sni != "" {
				m["tls"].(map[string]any)["server_name"] = sni
			}
		}
		return m

	case "ss":
		method, pass := extractSSMethod(raw)
		return map[string]any{
			"type": "shadowsocks", "tag": tag, "server": host, "server_port": port,
			"method": method, "password": pass,
		}

	default:
		return map[string]any{"type": "direct", "tag": tag}
	}
}

func extractUUID(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.User.Username()
	}
	return "00000000-0000-0000-0000-000000000000"
}
func extractPass(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.User.Username()
	}
	return ""
}
func extractSSMethod(raw string) (string, string) {
	after := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		after = raw[i+3:]
	}
	if idx := strings.Index(after, "#"); idx >= 0 {
		after = after[:idx]
	}
	decoded, err := base64.RawStdEncoding.DecodeString(after)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(after)
	}
	if err == nil {
		plain := string(decoded)
		if at := strings.LastIndex(plain, "@"); at >= 0 {
			userInfo := plain[:at]
			if parts := strings.SplitN(userInfo, ":", 2); len(parts) == 2 {
				return parts[0], parts[1]
			}
		}
	}
	return "none", ""
}
func orStr(v, fb string) string {
	if v != "" {
		return v
	}
	return fb
}
func trimLine(s string) string {
	if idx := strings.IndexAny(s, "\r\n"); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}
func trimStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func isXHTTPLink(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Query().Get("type"), "xhttp") || strings.EqualFold(u.Query().Get("network"), "xhttp")
}
