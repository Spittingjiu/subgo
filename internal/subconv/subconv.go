package subconv

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
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
	return ClashYAMLFromTemplate(links, nil)
}

// ClashYAMLFromTemplate generates clash config. If templateYAML is non-empty,
// it's used as the base (DNS, rules, rule-providers, etc.) and only proxies are overlaid.
func ClashYAMLFromTemplate(links []string, templateYAML []byte) (string, error) {
	proxies := []map[string]any{}
	names := []string{}
	for i, raw := range links {
		if px := clashProxy(raw, i+1); px != nil {
			proxies = append(proxies, px)
			names = append(names, fmt.Sprint(px["name"]))
		}
	}

	// If template provided, use it as base and overlay proxies
	if len(templateYAML) > 0 {
		var tmpl map[string]any
		if err := yaml.Unmarshal(templateYAML, &tmpl); err == nil {
			tmpl["proxies"] = proxies
			// Rebuild proxy-server-nameserver-policy with real node domains
			rebuildDNSProxyPolicy(tmpl, proxies)
			b, err := yaml.Marshal(tmpl)
			return string(b), err
		}
	}

	// Fallback: built-in template
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	root := map[string]any{
		"mixed-port": 7890, "allow-lan": true, "mode": "rule", "log-level": "info",
		"unified-delay": true, "tcp-concurrent": true, "ipv6": false,
		"sniffer": map[string]any{
			"enable": true,
			"sniff": map[string]any{
				"TLS":  map[string]any{"ports": []int{443, 8443}},
				"HTTP": map[string]any{"ports": []string{"80", "8080-8880"}},
			},
			"skip-domain": []string{"Mijia Cloud", "+.push.apple.com", "geosite:cn"},
		},
		"proxies": proxies,
		"proxy-groups": []map[string]any{
			{"name": "🚀 节点选择", "type": "select", "proxies": append([]string{"手动选择", "自动选择"}, names...)},
			{"name": "手动选择", "type": "select", "include-all": true, "proxies": []string{}, "exclude-filter": "^(?i:(DIRECT|REJECT|PASS))$"},
			{"name": "自动选择", "type": "url-test", "include-all": true, "proxies": []string{}, "url": "https://cp.cloudflare.com/generate_204", "interval": 600, "tolerance": 100, "exclude-filter": "^(?i:(DIRECT|REJECT|PASS))$"},
		},
		"rules": []string{
			"MATCH,🚀 节点选择",
		},
	}
	b, err := yaml.Marshal(root)
	return string(b), err
}

// rebuildDNSProxyPolicy updates dns.proxy-server-nameserver-policy with real node domains.
func rebuildDNSProxyPolicy(tmpl map[string]any, proxies []map[string]any) {
	dnsRaw, ok := tmpl["dns"]
	if !ok {
		return
	}
	dns, ok := dnsRaw.(map[string]any)
	if !ok {
		return
	}
	fixed := map[string]any{"geosite:cn": []string{"223.5.5.5", "119.29.29.29"}}
	seen := map[string]bool{"geosite:cn": true}
	for _, p := range proxies {
		server, _ := p["server"].(string)
		if server == "" || seen[server] {
			continue
		}
		seen[server] = true
		if net.ParseIP(server) != nil {
			continue
		}
		fixed[server] = []string{"223.5.5.5", "119.29.29.29"}
	}
	dns["proxy-server-nameserver-policy"] = fixed
}

func clashProxy(raw string, idx int) map[string]any {
	u, err := url.Parse(raw)
	p := ParseRawLink(raw)
	name := p.Name
	if name == "未命名节点" {
		name = fmt.Sprintf("node-%d", idx)
	}
	host := p.Host
	port := p.Port
	if host == "" && err == nil {
		host = u.Hostname()
	}
	if port == 0 && err == nil {
		port, _ = strconv.Atoi(u.Port())
	}
	if host == "" || port == 0 {
		return nil
	}
	if host == "" || port == 0 {
		return nil
	}
	var q url.Values
	if err == nil {
		q = u.Query()
	}
	security := strings.ToLower(first(q.Get("security"), "none"))
	network := strings.ToLower(first(q.Get("type"), "tcp"))
	fp := first(q.Get("fp"), "chrome")
	sni := first(q.Get("sni"), q.Get("host"))

	switch strings.ToLower(u.Scheme) {
	case "vless":
		m := map[string]any{
			"name": name, "type": "vless", "server": host, "port": port,
			"uuid": u.User.Username(), "udp": true, "network": network,
		}
		if security != "none" {
			m["tls"] = true
		}
		flow := q.Get("flow")
		if flow != "" && network != "xhttp" {
			m["flow"] = flow
		}
		if sni != "" {
			m["servername"] = sni
		}
		alpn := splitNonEmpty(q.Get("alpn"), ",")
		if len(alpn) > 0 {
			m["alpn"] = alpn
		}
		m["client-fingerprint"] = fp
		if network == "ws" {
			m["ws-opts"] = map[string]any{
				"path":    first(q.Get("path"), "/"),
				"headers": map[string]any{"Host": first(sni, host)},
			}
		}
		if network == "xhttp" {
			xhost := ""
			if security == "reality" && sni != "" {
				xhost = sni
			} else {
				xhost = q.Get("host")
			}
			xopts := map[string]any{"path": first(q.Get("path"), "/")}
			if xhost != "" {
				xopts["host"] = xhost
			}
			m["xhttp-opts"] = xopts
		}
		if security == "reality" || q.Get("pbk") != "" {
			ro := map[string]any{}
			if q.Get("pbk") != "" {
				ro["public-key"] = q.Get("pbk")
			}
			if q.Get("sid") != "" {
				ro["short-id"] = q.Get("sid")
			}
			if network != "xhttp" {
				spx := first(first(q.Get("spx"), q.Get("spiderx")), "/")
				ro["spider-x"] = spx
			}
			m["reality-opts"] = ro
		}
		return m
	case "hysteria2", "hy2":
		m := map[string]any{
			"name": name, "type": "hysteria2", "server": host, "port": port,
			"password": u.User.Username(), "udp": true,
		}
		if sni != "" {
			m["sni"] = sni
		}
		if q.Get("insecure") == "1" {
			m["skip-cert-verify"] = true
		}
		if alpn := splitNonEmpty(q.Get("alpn"), ","); len(alpn) > 0 {
			m["alpn"] = alpn
		}
		if q.Get("mport") != "" {
			m["ports"] = q.Get("mport")
		}
		if q.Get("mportInterval") != "" {
			if v, err := strconv.Atoi(q.Get("mportInterval")); err == nil && v > 0 {
				m["hop-interval"] = v
			}
		}
		return m
	case "trojan":
		m := map[string]any{
			"name": name, "type": "trojan", "server": host, "port": port,
			"password": u.User.Username(), "udp": true,
		}
		if sni != "" {
			m["sni"] = sni
		}
		return m
	case "ss":
		method, pass := "", ""
		// ss:// format: ss://base64(method:password@host:port)#name
		after := raw[strings.Index(raw, "://")+3:]
		if idx := strings.Index(after, "#"); idx >= 0 {
			after = after[:idx]
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(after); err == nil {
			plain := string(decoded)
			if at := strings.LastIndex(plain, "@"); at >= 0 {
				userInfo := plain[:at]
				if parts := strings.SplitN(userInfo, ":", 2); len(parts) == 2 {
					method, pass = parts[0], parts[1]
				}
			}
		} else if decoded, err := base64.StdEncoding.DecodeString(after); err == nil {
			plain := string(decoded)
			if at := strings.LastIndex(plain, "@"); at >= 0 {
				userInfo := plain[:at]
				if parts := strings.SplitN(userInfo, ":", 2); len(parts) == 2 {
					method, pass = parts[0], parts[1]
				}
			}
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

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, part := range strings.Split(s, sep) {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
