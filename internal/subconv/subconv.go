package subconv

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type ParsedLink struct {
	Protocol, Name, Host string
	Port                 int
}

func ParseRawLink(raw string) ParsedLink {
	raw = strings.TrimSpace(raw)
	p := ParsedLink{Protocol: "unknown", Name: "未命名节点"}
	if i := strings.Index(raw, "://"); i > 0 {
		p.Protocol = strings.ToLower(raw[:i])
	}
	// ss:// links: whole content is Base64(method:password@host:port)#name
	if p.Protocol == "ss" {
		after := raw[strings.Index(raw, "://")+3:]
		if idx := strings.Index(after, "#"); idx >= 0 {
			p.Name, _ = url.QueryUnescape(after[idx+1:])
			after = after[:idx]
		}
		decoded, err := base64.RawStdEncoding.DecodeString(after)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(after)
		}
		if err == nil {
			plain := string(decoded)
			if idx := strings.LastIndex(plain, "@"); idx >= 0 {
				p.Host = plain[idx+1:]
				if colon := strings.LastIndex(p.Host, ":"); colon >= 0 {
					p.Port, _ = strconv.Atoi(p.Host[colon+1:])
					p.Host = p.Host[:colon]
				}
			}
		}
		return p
	}
	if u, err := url.Parse(raw); err == nil {
		if u.Fragment != "" {
			if n, e := url.QueryUnescape(u.Fragment); e == nil && strings.TrimSpace(n) != "" {
				p.Name = strings.TrimSpace(n)
			}
		}
		p.Host = u.Hostname()
		if po := u.Port(); po != "" {
			p.Port, _ = strconv.Atoi(po)
		}
	}
	return p
}

func StableHash(raw string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(h[:])
}
func WithName(raw, name string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	u.Fragment = name
	return u.String()
}

func ParseSubscriptionText(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(text); err == nil && strings.Contains(string(decoded), "://") {
		text = string(decoded)
	} else if decoded, err := base64.RawStdEncoding.DecodeString(text); err == nil && strings.Contains(string(decoded), "://") {
		text = string(decoded)
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "://") {
			out = append(out, line)
		}
	}
	return out
}

func ClashYAML(links []string) (string, error) {
	proxies := []map[string]any{}
	names := []string{}
	for i, raw := range links {
		if px := clashProxy(raw, i+1); px != nil {
			proxies = append(proxies, px)
			names = append(names, fmt.Sprint(px["name"]))
		}
	}
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	root := map[string]any{
		"mixed-port": 7890, "allow-lan": true, "mode": "rule", "log-level": "info",
		"proxies":      proxies,
		"proxy-groups": []map[string]any{{"name": "🚀 节点选择", "type": "select", "proxies": append([]string{"DIRECT"}, names...)}},
		"rules":        []string{"MATCH,🚀 节点选择"},
	}
	b, err := yaml.Marshal(root)
	return string(b), err
}

func clashProxy(raw string, idx int) map[string]any {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	p := ParseRawLink(raw)
	name := p.Name
	if name == "未命名节点" {
		name = fmt.Sprintf("node-%d", idx)
	}
	q := u.Query()
	host := u.Hostname()
	port := p.Port
	if host == "" || port == 0 {
		return nil
	}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		m := map[string]any{"name": name, "type": "vless", "server": host, "port": port, "uuid": u.User.Username(), "network": first(q.Get("type"), "tcp"), "tls": q.Get("security") == "tls" || q.Get("security") == "reality", "udp": true}
		if q.Get("flow") != "" {
			m["flow"] = q.Get("flow")
		}
		if q.Get("sni") != "" {
			m["servername"] = q.Get("sni")
		}
		if q.Get("security") == "reality" || q.Get("pbk") != "" {
			ro := map[string]any{}
			if q.Get("pbk") != "" {
				ro["public-key"] = q.Get("pbk")
			}
			if q.Get("sid") != "" {
				ro["short-id"] = q.Get("sid")
			}
			m["reality-opts"] = ro
		}
		return m
	case "hysteria2", "hy2":
		m := map[string]any{"name": name, "type": "hysteria2", "server": host, "port": port, "password": u.User.Username(), "udp": true}
		if q.Get("sni") != "" {
			m["sni"] = q.Get("sni")
		}
		if q.Get("insecure") == "1" {
			m["skip-cert-verify"] = true
		}
		return m
	case "trojan":
		m := map[string]any{"name": name, "type": "trojan", "server": host, "port": port, "password": u.User.Username(), "udp": true}
		if q.Get("sni") != "" {
			m["sni"] = q.Get("sni")
		}
		return m
	case "ss":
		method := u.User.Username()
		pass, _ := u.User.Password()
		if strings.Contains(method, ":") {
			parts := strings.SplitN(method, ":", 2)
			method = parts[0]
			pass = parts[1]
		}
		return map[string]any{"name": name, "type": "ss", "server": host, "port": port, "cipher": method, "password": pass, "udp": true}
	default:
		return nil
	}
}
func first(v, fb string) string {
	if v != "" {
		return v
	}
	return fb
}
