package subconv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Issue is deliberately safe to serialize. Reasons and paths never include
// parser error text, URI queries, endpoints, credentials or template values.
type Issue struct {
	Index  int    `json:"index,omitempty"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
	Path   string `json:"path,omitempty"`
}

type Item struct {
	Index      int    `json:"index"`
	NodeID     int64  `json:"node_id,omitempty"`
	NodeHash   string `json:"node_hash,omitempty"`
	SourceID   int64  `json:"source_id,omitempty"`
	SourceName string `json:"source_name,omitempty"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Status     string `json:"status"`
	Code       string `json:"code"`
	Reason     string `json:"reason"`
}

// Report.Valid means that no conversion/validation errors remain. Policy skips
// (disabled, missing, duplicate selections or auto-pruned nodes) are warnings.
// A partial conversion can still render a usable YAML, but Valid is then false.
// A final-config reference/structure error always returns no YAML and an error.
type Report struct {
	InputCount     int     `json:"input_count"`
	ConvertedCount int     `json:"converted_count"`
	SkippedCount   int     `json:"skipped_count"`
	Valid          bool    `json:"valid"`
	Errors         []Issue `json:"errors"`
	Warnings       []Issue `json:"warnings"`
	Items          []Item  `json:"items"`
}

// ConversionInput is an internal export candidate, not an API request/response.
// Skips let the subscription service include disabled/missing nodes in counts
// without passing their raw links through the converter.
type ConversionInput struct {
	RawLink    string `json:"-"`
	NodeID     int64  `json:"-"`
	NodeHash   string `json:"-"`
	SourceID   int64  `json:"-"`
	SourceName string `json:"-"`
	Name       string `json:"-"`
	Protocol   string `json:"-"`
	SkipCode   string `json:"-"`
	SkipReason string `json:"-"`
}

func (r *Report) AddError(code, reason string) {
	r.Errors = append(r.Errors, Issue{Code: code, Reason: reason})
	r.Valid = false
}

func (r *Report) AddWarning(code, reason string) {
	r.Warnings = append(r.Warnings, Issue{Code: code, Reason: reason})
}

func ClashYAMLWithReport(links []string) (string, Report, error) {
	return ClashYAMLFromTemplateWithReport(links, nil)
}

func ClashYAMLFromTemplateWithReport(links []string, templateYAML []byte) (string, Report, error) {
	inputs := make([]ConversionInput, len(links))
	for i, raw := range links {
		inputs[i].RawLink = raw
	}
	return ClashYAMLForInputs(inputs, templateYAML)
}

func ClashYAMLForInputs(inputs []ConversionInput, templateYAML []byte) (string, Report, error) {
	report := Report{InputCount: len(inputs), Valid: true, Errors: []Issue{}, Warnings: []Issue{}, Items: make([]Item, len(inputs))}
	var root map[string]any
	var templateErr error
	if len(templateYAML) > 0 {
		root, templateErr = parseTemplate(templateYAML)
		if templateErr != nil {
			report.AddError("invalid_template", "The configured template is not a usable YAML document; no silent fallback was used.")
		}
	}
	secrets := reportSecrets(inputs)
	type candidate struct {
		index    int
		proxy    map[string]any
		base     string
		identity string
	}
	candidates := []candidate{}
	for i, input := range inputs {
		name := fragmentName(input.RawLink)
		if input.Name != "" {
			name = input.Name
		}
		if name == "未命名节点" || strings.TrimSpace(name) == "" {
			if input.NodeID > 0 {
				name = fmt.Sprintf("node-%d", input.NodeID)
			} else {
				name = fmt.Sprintf("node-%d", i+1)
			}
		}
		name = safeReportName(name, secrets)
		protocol := diagnosticProtocol(input.RawLink)
		if input.RawLink == "" {
			protocol = diagnosticProtocol(input.Protocol + "://")
		}
		sourceName := input.SourceName
		if sourceName != "" {
			sourceName = safeReportName(sourceName, secrets)
		}
		item := Item{Index: i + 1, NodeID: input.NodeID, NodeHash: safeReportHash(input.NodeHash, secrets), SourceID: input.SourceID, SourceName: sourceName, Name: name, Protocol: protocol, Status: "skipped"}
		if input.SkipCode != "" {
			item.Code, item.Reason = input.SkipCode, input.SkipReason
			// Skip reasons are fixed strings supplied by the service, not clients.
			report.Warnings = append(report.Warnings, Issue{Index: i + 1, Code: item.Code, Reason: item.Reason})
			report.SkippedCount++
			report.Items[i] = item
			continue
		}
		proxy, issue, warnings := convertProxy(input.RawLink, i+1)
		if issue != nil {
			item.Code, item.Reason = issue.Code, issue.Reason
			issue.Index = i + 1
			report.Errors = append(report.Errors, *issue)
			report.SkippedCount++
			report.Items[i] = item
			continue
		}
		for _, warning := range warnings {
			warning.Index = i + 1
			report.Warnings = append(report.Warnings, warning)
		}
		proxy["name"] = name
		item.Status, item.Code, item.Reason = "converted", "converted", "Converted to a Mihomo proxy."
		report.Items[i] = item
		report.ConvertedCount++
		candidates = append(candidates, candidate{index: i, proxy: proxy, base: name, identity: StableHash(input.RawLink)})
	}

	// Use one namespace for built-ins, every group, every original proxy name
	// and every generated suffix. Stable link identity, not input/source order,
	// chooses which duplicate retains its original name.
	used := reservedNames(root)
	original := map[string]bool{}
	for _, c := range candidates {
		original[c.base] = true
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.base != b.base {
			return a.base < b.base
		}
		if a.identity != b.identity {
			return a.identity < b.identity
		}
		if inputs[a.index].NodeID != inputs[b.index].NodeID {
			return inputs[a.index].NodeID < inputs[b.index].NodeID
		}
		return a.index < b.index
	})
	for _, c := range candidates {
		name := c.base
		if used[name] {
			for suffix := 2; ; suffix++ {
				name = fmt.Sprintf("%s-%d", c.base, suffix)
				if !used[name] && !original[name] {
					break
				}
			}
		}
		used[name] = true
		c.proxy["name"] = name
		report.Items[c.index].Name = name
		if name != c.base {
			report.Items[c.index].Code = "name_renamed"
			report.Items[c.index].Reason = "Converted with a deterministic unique name to avoid a proxy/group/built-in collision."
			report.Warnings = append(report.Warnings, Issue{Index: c.index + 1, Code: "name_renamed", Reason: report.Items[c.index].Reason})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].index < candidates[j].index })
	proxies := make([]map[string]any, 0, len(candidates))
	names := make([]string, 0, len(candidates))
	for _, c := range candidates {
		proxies = append(proxies, c.proxy)
		names = append(names, c.proxy["name"].(string))
	}
	if len(inputs) == 0 {
		report.AddWarning("empty_input", "There are no input nodes; no proxies were generated.")
	}
	if templateErr != nil {
		report.Valid = false
		return "", report, templateErr
	}
	if report.ConvertedCount == 0 && len(report.Errors) > 0 {
		// An unsupported-only selection must not look like a DIRECT-only export.
		// Explicit empty inputs and policy-only skips keep their existing behavior.
		report.Valid = false
		return "", report, errors.New("no input nodes can be converted for the supported Mihomo target")
	}
	if root != nil {
		root["proxies"] = proxies
		rebuildDNSProxyPolicy(root, proxies)
	} else {
		out, err := builtInTemplate(proxies, names)
		if err != nil || yaml.Unmarshal([]byte(out), &root) != nil {
			report.AddError("yaml_encoding_failed", "The converted configuration could not be encoded.")
			return "", report, errors.New("configuration encoding failed")
		}
	}
	if issues := validateConfig(root); len(issues) > 0 {
		report.Errors = append(report.Errors, issues...)
		report.Valid = false
		return "", report, errors.New("converted configuration has invalid references or structure")
	}
	data, err := yaml.Marshal(root)
	if err != nil {
		report.AddError("yaml_encoding_failed", "The converted configuration could not be encoded.")
		return "", report, errors.New("configuration encoding failed")
	}
	report.Valid = len(report.Errors) == 0
	return string(data), report, nil
}

func diagnosticProtocol(raw string) string {
	protocol := protocolOf(strings.TrimSpace(raw))
	switch protocol {
	case "ss", "ssr", "vless", "vmess", "trojan", "trojan-go", "anytls", "hy2", "hysteria2", "hysteria", "tuic", "wireguard", "socks", "socks5", "http", "https", "ssh":
		return protocol
	default:
		return "unknown"
	}
}

// Report names are display-only. Credentials embedded in malicious fragments or
// DB names are redacted too; rejecting only a raw_link field would be insufficient.
func safeReportName(name string, secrets []string) string {
	if strings.Contains(name, "://") || strings.Contains(strings.ToLower(name), "bearer ") {
		return "redacted-node"
	}
	for _, secret := range secrets {
		if secret != "" && ((len(secret) >= 3 && strings.Contains(name, secret)) || name == secret) {
			name = strings.ReplaceAll(name, secret, "[redacted]")
		}
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	runes := []rune(name)
	if len(runes) > 180 {
		name = string(runes[:180])
	}
	if name == "" {
		return "unnamed-node"
	}
	return name
}

func safeReportHash(hash string, secrets []string) string {
	// Existing/missing SHA256 identities may be returned to the management UI,
	// but corrupt legacy selection data must not become a raw-URI/token echo.
	if len(hash) > 256 || strings.Contains(hash, "://") || strings.Contains(strings.ToLower(hash), "bearer ") || strings.IndexFunc(hash, unicode.IsControl) >= 0 {
		return ""
	}
	for _, secret := range secrets {
		if hash != "" && secret == hash {
			return ""
		}
	}
	return hash
}

func reportSecrets(inputs []ConversionInput) []string {
	seen := map[string]bool{}
	add := func(value string) {
		if value != "" {
			seen[value] = true
			seen[url.QueryEscape(value)] = true
			seen[url.PathEscape(value)] = true
		}
	}
	for _, input := range inputs {
		p, _ := parseProxyURI(input.RawLink)
		add(p.password)
		if p.user != nil {
			add(p.user.Username())
			if password, present := p.user.Password(); present {
				add(password)
			}
		}
		if p.cipher != "" && p.password != "" {
			for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
				add(encoding.EncodeToString([]byte(p.cipher + ":" + p.password)))
			}
		}
		for key, values := range p.query {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || lower == "auth" || lower == "encryption" || lower == "key" {
				for _, value := range values {
					add(value)
				}
			}
		}
		// Extract userinfo/query separately even when endpoint parsing failed.
		raw := input.RawLink
		if start := strings.Index(raw, "://"); start >= 0 {
			authority := raw[start+3:]
			if end := strings.IndexAny(authority, "?#"); end >= 0 {
				authority = authority[:end]
			}
			// Also redact opaque legacy/unsupported payloads if they were copied
			// into a display name; no protocol credential parsing is inferred.
			add(authority)
			if at := strings.LastIndexByte(authority, '@'); at >= 0 {
				userinfo := authority[:at]
				add(userinfo)
				if decoded, err := url.PathUnescape(userinfo); err == nil {
					if method, password, found := strings.Cut(decoded, ":"); found {
						add(method)
						add(password)
					} else {
						add(decoded)
					}
				}
			}
		}
		if query := strings.IndexByte(raw, '?'); query >= 0 {
			value := raw[query+1:]
			if end := strings.IndexByte(value, '#'); end >= 0 {
				value = value[:end]
			}
			if q, err := url.ParseQuery(value); err == nil {
				for key, values := range q {
					lower := strings.ToLower(key)
					if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || lower == "auth" || lower == "encryption" || lower == "key" {
						for _, value := range values {
							add(value)
						}
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	// Longest first avoids leaking a suffix after partially redacting a secret.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}
