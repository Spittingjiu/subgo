package subconv

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
)

type ParsedLink struct{ Protocol, Name string }

func ParseRawLink(raw string) ParsedLink {
	raw = strings.TrimSpace(raw)
	p := ParsedLink{Protocol: "unknown", Name: "未命名节点"}
	if i := strings.Index(raw, "://"); i > 0 {
		p.Protocol = strings.ToLower(raw[:i])
	}
	if u, err := url.Parse(raw); err == nil {
		if u.Fragment != "" {
			if n, e := url.QueryUnescape(u.Fragment); e == nil && strings.TrimSpace(n) != "" {
				p.Name = strings.TrimSpace(n)
			}
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
