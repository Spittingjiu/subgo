package subconv

import (
	"encoding/base64"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// URI mappings are based on Shadowsocks SIP002, Hysteria 2's URI scheme and
// MetaCubeX/mihomo's outbound/transport documentation (see conversion.md).
// All parser failures use fixed messages: net/url errors can contain userinfo.
type proxyURI struct {
	scheme, name, host, cipher, password string
	port                                 int
	ports                                string
	user                                 *url.Userinfo
	query                                url.Values
}

func protocolOf(raw string) string {
	if i := strings.Index(raw, "://"); i > 0 {
		protocol := strings.ToLower(raw[:i])
		if len(protocol) <= 24 {
			for _, r := range protocol {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.') {
					return "unknown"
				}
			}
			return protocol
		}
	}
	return "unknown"
}

func fragmentName(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		// Decode exactly once, preserving legacy '+'-as-space display names.
		if name, err := url.QueryUnescape(raw[i+1:]); err == nil && strings.TrimSpace(name) != "" {
			return strings.TrimSpace(name)
		}
	}
	return "未命名节点"
}

func numericPort(raw string) int {
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > 65535 {
		return 0
	}
	return v
}

func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if data, err := enc.Strict().DecodeString(s); err == nil && utf8.Valid(data) {
			return data, true
		}
	}
	return nil, false
}

func validHost(host string) bool {
	if host == "" || strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || strings.ContainsAny(host, "/@?#[]\\") {
		return false
	}
	if strings.Contains(host, ":") {
		ip := host
		if i := strings.LastIndexByte(ip, '%'); i >= 0 {
			if i == len(ip)-1 {
				return false
			}
			ip = ip[:i]
		}
		return net.ParseIP(ip) != nil
	}
	return true
}

func invalidURI(code, reason string) *Issue { return &Issue{Code: code, Reason: reason} }

func parseShadowsocksURI(raw string) (proxyURI, *Issue) {
	p := proxyURI{scheme: "ss", name: fragmentName(raw), query: url.Values{}}
	body := strings.TrimSpace(raw)
	if protocolOf(body) != "ss" {
		return p, invalidURI("invalid_uri", "The node is not a Shadowsocks URI.")
	}
	body = body[strings.Index(body, "://")+3:]
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		q, err := url.ParseQuery(body[i+1:])
		if err != nil {
			return p, invalidURI("invalid_query", "The URI query is malformed or not percent-encoded.")
		}
		p.query, body = q, body[:i]
	}
	body = strings.TrimSuffix(body, "/")
	var auth, address string
	encodedUserinfo := false
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		auth, address = body[:at], body[at+1:]
		var err error
		auth, err = url.PathUnescape(auth)
		if err != nil {
			return p, invalidURI("invalid_ss_userinfo", "Shadowsocks userinfo has invalid percent encoding.")
		}
		if !strings.Contains(auth, ":") {
			decoded, ok := decodeBase64(auth)
			if !ok {
				return p, invalidURI("invalid_ss_userinfo", "Shadowsocks userinfo is not valid Base64URL method:password.")
			}
			auth, encodedUserinfo = string(decoded), true
		}
	} else {
		// Legacy ss://BASE64(method:password@host:port); padded/unpadded
		// standard and URL-safe Base64 are accepted, including bracketed IPv6.
		decoded, ok := decodeBase64(body)
		if !ok {
			return p, invalidURI("invalid_ss_legacy", "The legacy Shadowsocks payload is not valid Base64.")
		}
		plain := string(decoded)
		at := strings.LastIndexByte(plain, '@')
		if at < 0 {
			return p, invalidURI("invalid_ss_legacy", "The legacy Shadowsocks payload has no endpoint.")
		}
		auth, address, encodedUserinfo = plain[:at], plain[at+1:], true
	}
	method, password, ok := strings.Cut(auth, ":")
	if !ok || method == "" || strings.ContainsAny(method, " \t\r\n") {
		return p, invalidURI("invalid_ss_userinfo", "Shadowsocks userinfo must contain a cipher and password.")
	}
	p.cipher, p.password = strings.ToLower(method), password
	if strings.HasPrefix(p.cipher, "2022-") && encodedUserinfo {
		return p, invalidURI("invalid_ss_2022_userinfo", "SIP002 requires percent-encoded plaintext userinfo for AEAD-2022, not Base64 userinfo.")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || !validHost(host) || numericPort(port) == 0 {
		return p, invalidURI("invalid_endpoint", "The node requires a hostname and port in 1–65535; IPv6 endpoints must be bracketed.")
	}
	p.host, p.port = host, numericPort(port)
	return p, nil
}

func parseProxyURI(raw string) (proxyURI, *Issue) {
	raw = strings.TrimSpace(raw)
	p := proxyURI{scheme: protocolOf(raw), name: fragmentName(raw)}
	if p.scheme == "ss" {
		return parseShadowsocksURI(raw)
	}
	switch p.scheme {
	case "vless", "trojan", "anytls", "hysteria2", "hy2":
	default:
		return p, invalidURI("unsupported_protocol", "This protocol has no supported Mihomo URI conversion.")
	}
	// net/url intentionally rejects non-numeric ports. HY2's official URI
	// permits port sets; extract/validate them first and parse a numeric surrogate.
	parseRaw := raw
	if p.scheme == "hy2" || p.scheme == "hysteria2" {
		body := raw[strings.Index(raw, "://")+3:]
		end := strings.IndexAny(body, "/?#")
		if end < 0 {
			end = len(body)
		}
		authority := body[:end]
		address := authority
		prefix := ""
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			prefix, address = authority[:at+1], authority[at+1:]
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			// Omitted HY2 port defaults to 443; a malformed explicit port or
			// unbracketed IPv6 must not be mistaken for an omitted port.
			host = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
			if !validHost(host) || (!strings.HasPrefix(address, "[") && strings.Contains(address, ":")) || (strings.HasPrefix(address, "[") && !strings.HasSuffix(address, "]")) {
				return p, invalidURI("invalid_endpoint", "The Hysteria 2 endpoint is malformed; IPv6 endpoints must be bracketed.")
			}
			port = "443"
		}
		firstPort, valid := validatePortSet(port)
		if !valid {
			return p, invalidURI("invalid_ports", "Hysteria 2 ports must be a port or comma-separated ascending port ranges in 1–65535.")
		}
		if strings.ContainsAny(port, ",-:") {
			p.ports = strings.ReplaceAll(port, ":", "-")
		}
		parseRaw = p.scheme + "://" + prefix + net.JoinHostPort(host, strconv.Itoa(firstPort)) + body[end:]
	}
	u, err := url.Parse(parseRaw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return p, invalidURI("invalid_uri", "The URI is malformed or has no network endpoint.")
	}
	p.host, p.port, p.user = u.Hostname(), numericPort(u.Port()), u.User
	if !validHost(p.host) || p.port == 0 {
		return p, invalidURI("invalid_endpoint", "The node requires a hostname and port in 1–65535; IPv6 endpoints must be bracketed.")
	}
	if u.Path != "" && u.Path != "/" {
		return p, invalidURI("unsupported_uri_path", "Transport paths must be in URI query parameters, not in the URI authority path.")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return p, invalidURI("invalid_query", "The URI query is malformed or not percent-encoded.")
	}
	p.query = q
	if u.User != nil {
		p.password = u.User.Username()
		if password, hasPassword := u.User.Password(); hasPassword {
			if p.scheme != "hy2" && p.scheme != "hysteria2" {
				return p, invalidURI("unsupported_userinfo", "A password containing a colon must be percent-encoded as one userinfo value.")
			}
			// HY2 userpass is explicitly username:password, not username alone.
			p.password += ":" + password
		}
	}
	return p, nil
}

// validatePortSet does not enumerate ranges or perform network lookups.
func validatePortSet(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	firstPort := 0
	for _, part := range strings.Split(raw, ",") {
		part = strings.ReplaceAll(part, ":", "-")
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return 0, false
		}
		start := numericPort(bounds[0])
		if start == 0 {
			return 0, false
		}
		if len(bounds) == 2 && (numericPort(bounds[1]) == 0 || numericPort(bounds[1]) < start) {
			return 0, false
		}
		if firstPort == 0 {
			firstPort = start
		}
	}
	return firstPort, true
}

func ambiguousQuery(q url.Values) bool {
	for _, values := range q {
		for i := 1; i < len(values); i++ {
			if values[i] != values[0] {
				return true
			}
		}
	}
	return false
}

func queryAlias(q url.Values, keys ...string) (string, bool, *Issue) {
	value, present := "", false
	for _, key := range keys {
		if values, ok := q[key]; ok && len(values) > 0 {
			if present && value != values[0] {
				return "", true, invalidURI("ambiguous_parameter", "Conflicting aliases of the same connection parameter cannot be converted safely.")
			}
			value, present = values[0], true
		}
	}
	return value, present, nil
}

func queryBool(q url.Values, keys ...string) (bool, bool, *Issue) {
	value, present, issue := queryAlias(q, keys...)
	if issue != nil || !present {
		return false, present, issue
	}
	v, err := strconv.ParseBool(value)
	if err != nil {
		return false, true, invalidURI("invalid_boolean", "A TLS or transport boolean parameter must be true/false or 1/0.")
	}
	return v, true, nil
}
