package subconv

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

type ParsedLink struct {
	Protocol, Name, Host string
	Port                 int
}

func ParseRawLink(raw string) ParsedLink {
	raw = strings.TrimSpace(raw)
	p := ParsedLink{Protocol: protocolOf(raw), Name: fragmentName(raw)}
	if p.Protocol == "ss" {
		link, issue := parseShadowsocksURI(raw)
		if issue == nil {
			p.Host, p.Port = link.host, link.port
		}
		return p
	}
	// Retain the coarse identity model; only the SS URI parsing is repaired.
	if u, err := url.Parse(raw); err == nil {
		p.Host = u.Hostname()
		p.Port = numericPort(u.Port())
	}
	return p
}

func StableHash(raw string) string {
	h := sha256.Sum256([]byte(StableHashInput(raw)))
	return hex.EncodeToString(h[:])
}

// StableHashInput returns the canonical identity string used for node_hash.
// Subscription selections must survive display-name/remark changes, which are
// stored in the URL fragment (#name). Keep all connection-affecting parts, but
// deliberately drop the fragment so renames do not orphan subscriptions.
func StableHashInput(raw string) string {
	canonical := strings.TrimSpace(raw)
	if u, err := url.Parse(canonical); err == nil && u.Scheme != "" {
		u.Fragment = ""
		canonical = u.String()
	}
	return strings.TrimSpace(canonical)
}
func WithName(raw, name string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	u.Fragment = name
	return u.String()
}

// NodeIdentity returns a coarse identity key for a link: protocol + host + port.
// Unlike node_hash (which covers every connection parameter), this survives
// upstream rotations of uuid/password, REALITY key pairs, short ids, flow flags
// and display names. It lets subgo keep the same node row - and therefore every
// subscription entry that points at it - when a panel regenerates its link.
func NodeIdentity(raw string) string {
	p := ParseRawLink(strings.TrimSpace(raw))
	host := strings.ToLower(strings.TrimSpace(p.Host))
	if host == "" {
		return ""
	}
	return fmt.Sprintf("%s|%s|%d", strings.ToLower(p.Protocol), host, p.Port)
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

// TemplateInfo summarises a Clash template that passed validation.
type TemplateInfo struct {
	ProxyGroups int
	Rules       int
}

// ValidateTemplate checks that body is a usable Clash template before it is
// cached and served. Upstream templates are hand-edited and the overlay step can
// only substitute proxies, so an unparseable template used to fall through to
// the built-in minimal config without a word - dropping every policy group and
// every routing rule from all subscriptions at once.
func ValidateTemplate(body []byte) (TemplateInfo, error) {
	var info TemplateInfo
	tmpl, err := parseTemplate(body)
	if err != nil {
		return info, err
	}
	if issues := validateConfig(tmpl); len(issues) > 0 {
		return info, errors.New("template has invalid configuration references or structure")
	}
	if groups, ok := tmpl["proxy-groups"].([]any); ok {
		info.ProxyGroups = len(groups)
	}
	if rules, ok := tmpl["rules"].([]any); ok {
		info.Rules = len(rules)
	}
	return info, nil
}

// ClashYAMLFromTemplate preserves the original API. New callers should use
// ClashYAMLFromTemplateWithReport to see every skipped node and validation issue.
func ClashYAMLFromTemplate(links []string, templateYAML []byte) (string, error) {
	out, report, err := ClashYAMLFromTemplateWithReport(links, templateYAML)
	if report.SkippedCount > 0 || !report.Valid || len(report.Warnings) > 0 {
		log.Printf("[subconv] input=%d converted=%d skipped=%d valid=%t errors=%d warnings=%d", report.InputCount, report.ConvertedCount, report.SkippedCount, report.Valid, len(report.Errors), len(report.Warnings))
	}
	return out, err
}

// builtInTemplate is the last-resort config used when no valid upstream template
// is available. It deliberately keeps mainland traffic - WeChat included - on
// DIRECT: the previous fallback sent everything through the proxy, which is what
// broke WeChat image uploads the moment the upstream template failed to parse.
func builtInTemplate(proxies []map[string]any, names []string) (string, error) {
	if len(names) == 0 {
		names = []string{"DIRECT"}
	}
	root := map[string]any{
		"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "info",
		"unified-delay": true, "tcp-concurrent": true, "ipv6": false,
		"dns": map[string]any{
			"enable":             true,
			"ipv6":               false,
			"enhanced-mode":      "fake-ip",
			"fake-ip-range":      "198.18.0.1/16",
			"default-nameserver": []string{"223.5.5.5", "119.29.29.29"},
			"nameserver":         []string{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"},
			"fake-ip-filter": []string{
				"*.lan",
				"*.local",
				"localhost.ptlogin2.qq.com",
				"+.qq.com",
				"+.tencent.com",
				"+.wechat.com",
				"+.weixin.qq.com",
				"+.qpic.cn",
				"+.qlogo.cn",
				"+.myqcloud.com",
				"geosite:cn",
			},
		},
		"sniffer": map[string]any{
			"enable": true,
			"sniff": map[string]any{
				"TLS":  map[string]any{"ports": []int{443, 8443}},
				"HTTP": map[string]any{"ports": []string{"80", "8080-8880"}},
			},
			"skip-domain": []string{"Mijia Cloud", "+.push.apple.com", "+.qq.com", "+.weixin.qq.com", "+.qpic.cn", "geosite:cn"},
		},
		"proxies": proxies,
		"proxy-groups": []map[string]any{
			{"name": "🚀 节点选择", "type": "select", "proxies": append([]string{"手动选择", "自动选择"}, names...)},
			{"name": "手动选择", "type": "select", "include-all": true, "proxies": []string{}, "exclude-filter": "^(?i:(DIRECT|REJECT|PASS))$"},
			{"name": "自动选择", "type": "url-test", "include-all": true, "proxies": []string{}, "url": "https://cp.cloudflare.com/generate_204", "interval": 600, "tolerance": 100, "exclude-filter": "^(?i:(DIRECT|REJECT|PASS))$"},
		},
		"rules": []string{
			"DOMAIN-SUFFIX,qpic.cn,DIRECT",
			"DOMAIN-SUFFIX,qlogo.cn,DIRECT",
			"DOMAIN-SUFFIX,weixin.qq.com,DIRECT",
			"DOMAIN-SUFFIX,wechat.com,DIRECT",
			"DOMAIN-SUFFIX,qq.com,DIRECT",
			"DOMAIN-SUFFIX,tencent.com,DIRECT",
			"DOMAIN-SUFFIX,myqcloud.com,DIRECT",
			"GEOSITE,cn,DIRECT",
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

// ClashProxy converts one raw subscription link into one Mihomo/Clash proxy.
func ClashProxy(raw string) map[string]any {
	return clashProxy(raw, 1)
}

func clashProxy(raw string, idx int) map[string]any {
	px, issue, _ := convertProxy(raw, idx)
	if issue != nil {
		// Deliberately log only a fixed diagnostic code, never the raw link,
		// userinfo, endpoint query, display name or parser error text.
		log.Printf("[subconv] conversion skipped: code=%s", issue.Code)
	}
	return px
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
