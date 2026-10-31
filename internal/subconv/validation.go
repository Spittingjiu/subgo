package subconv

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var builtinProxyNames = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
var builtinGroupNames = []string{"🚀 节点选择", "手动选择", "自动选择"}

func parseTemplate(body []byte) (map[string]any, error) {
	var root map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&root); err != nil || len(root) == 0 {
		return nil, errors.New("template is not a non-empty YAML mapping")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("template must contain exactly one YAML document")
	}
	return root, nil
}

func reservedNames(root map[string]any) map[string]bool {
	names := map[string]bool{}
	for _, name := range builtinProxyNames {
		names[name] = true
	}
	if root == nil {
		for _, name := range builtinGroupNames {
			names[name] = true
		}
	} else if groups, ok := configList(root["proxy-groups"]); ok {
		for _, value := range groups {
			if group, ok := value.(map[string]any); ok {
				if name, ok := group["name"].(string); ok {
					names[name] = true
				}
			}
		}
	}
	return names
}

func configList(value any) ([]any, bool) {
	if value == nil {
		return nil, true
	}
	switch value := value.(type) {
	case []any:
		return value, true
	case []string:
		out := make([]any, len(value))
		for i, v := range value {
			out[i] = v
		}
		return out, true
	case []map[string]any:
		out := make([]any, len(value))
		for i, v := range value {
			out[i] = v
		}
		return out, true
	default:
		return nil, false
	}
}

// validateConfig is a local structure/reference validator, not a replacement
// for a version-specific Mihomo parser or a connectivity test. Provider payloads
// are not fetched. In particular, provider names must be referenced through use,
// and explicit proxies/rules must refer to local proxies/groups or built-ins.
func validateConfig(root map[string]any) []Issue {
	issues := []Issue{}
	add := func(code, reason, path string) {
		issues = append(issues, Issue{Code: code, Reason: reason, Path: path})
	}
	known := map[string]string{}
	for _, name := range builtinProxyNames {
		known[name] = "builtin"
	}
	proxies, ok := configList(root["proxies"])
	if !ok {
		add("invalid_proxies", "The proxies field must be a list.", "proxies")
	}
	groups, ok := configList(root["proxy-groups"])
	if !ok {
		add("invalid_proxy_groups", "The proxy-groups field must be a list.", "proxy-groups")
	}
	graph := map[string][]string{}
	for _, section := range []struct {
		key, kind string
		values    []any
	}{{"proxies", "proxy", proxies}, {"proxy-groups", "group", groups}} {
		for i, value := range section.values {
			path := fmt.Sprintf("%s[%d]", section.key, i)
			entry, ok := value.(map[string]any)
			if !ok {
				add("invalid_named_entry", "A proxy or group entry must be a mapping.", path)
				continue
			}
			name, isString := entry["name"].(string)
			if !isString || strings.TrimSpace(name) == "" {
				add("missing_name", "Every proxy and group requires a non-empty string name.", path+".name")
				continue
			}
			if _, present := known[name]; present {
				add("duplicate_name", "Proxy, group and built-in names must be globally unique.", path+".name")
				continue
			}
			known[name] = section.kind
			if typ, ok := entry["type"].(string); !ok || strings.TrimSpace(typ) == "" {
				add("missing_type", "Every proxy and group requires a type.", path+".type")
			}
		}
	}
	providers := configProviders(root, "proxy-providers", &issues)
	ruleProviders := configProviders(root, "rule-providers", &issues)
	for i, value := range groups {
		group, ok := value.(map[string]any)
		if !ok {
			continue
		}
		name, _ := group["name"].(string)
		path := fmt.Sprintf("proxy-groups[%d]", i)
		refs, valid := configList(group["proxies"])
		if !valid {
			add("invalid_group_references", "Group proxies must be a list of proxy/group names.", path+".proxies")
		}
		for j, value := range refs {
			ref, valid := value.(string)
			if !valid || known[ref] == "" {
				add("dangling_group_reference", "The group references an absent proxy or group after the template overlay.", fmt.Sprintf("%s.proxies[%d]", path, j))
			} else if known[ref] != "builtin" {
				graph[name] = append(graph[name], ref)
			}
		}
		uses, valid := configList(group["use"])
		if !valid {
			add("invalid_provider_references", "Group use must be a list of proxy-provider names.", path+".use")
		}
		for j, value := range uses {
			ref, valid := value.(string)
			if !valid || !providers[ref] {
				add("missing_proxy_provider", "The group references an absent proxy-provider.", fmt.Sprintf("%s.use[%d]", path, j))
			}
		}
		for _, key := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
			if value, present := group[key]; present {
				if _, valid := value.(bool); !valid {
					add("invalid_include_all", "Group include-all settings must be booleans.", path+"."+key)
				}
			}
		}
		if value, present := group["empty-fallback"]; present {
			ref, valid := value.(string)
			if !valid || known[ref] == "" || known[ref] == "group" {
				add("invalid_empty_fallback", "A group's empty-fallback must reference a proxy or built-in, not another group.", path+".empty-fallback")
			}
		}
	}
	for i, value := range proxies {
		proxy, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if value, present := proxy["dialer-proxy"]; present {
			ref, valid := value.(string)
			name, _ := proxy["name"].(string)
			if !valid || known[ref] == "" {
				add("dangling_dialer_reference", "A proxy dialer references an absent proxy or group.", fmt.Sprintf("proxies[%d].dialer-proxy", i))
			} else if known[ref] != "builtin" {
				graph[name] = append(graph[name], ref)
			}
		}
	}
	if hasReferenceCycle(graph) {
		add("proxy_reference_cycle", "Proxy/group references contain a cycle.", "proxy-groups")
	}
	for _, key := range []string{"proxy-providers", "rule-providers"} {
		if entries, ok := root[key].(map[string]any); ok {
			// Paths contain only numeric positions, never provider names/tokens.
			names := make([]string, 0, len(entries))
			for name := range entries {
				names = append(names, name)
			}
			sort.Strings(names)
			for i, name := range names {
				entry, _ := entries[name].(map[string]any)
				if value, present := entry["proxy"]; present {
					ref, valid := value.(string)
					if !valid || known[ref] == "" {
						add("dangling_provider_proxy", "A provider download proxy references an absent proxy or group.", fmt.Sprintf("%s[%d].proxy", key, i))
					}
				}
			}
		}
	}
	subRules := map[string]any{}
	if value, present := root["sub-rules"]; present {
		var valid bool
		subRules, valid = value.(map[string]any)
		if !valid {
			add("invalid_sub_rules", "The sub-rules field must be a mapping of rule lists.", "sub-rules")
			subRules = map[string]any{}
		}
	}
	subGraph := map[string][]string{}
	checkRules := func(value any, path, subName string) {
		rules, valid := configList(value)
		if !valid {
			add("invalid_rules", "Rules must be a list of strings.", path)
			return
		}
		for i, value := range rules {
			where := fmt.Sprintf("%s[%d]", path, i)
			rule, valid := value.(string)
			if !valid {
				add("invalid_rule", "A rule must be a string with a policy target.", where)
				continue
			}
			fields, valid := splitRule(rule)
			if !valid || len(fields) < 2 {
				add("invalid_rule", "A rule must contain a valid expression and policy target.", where)
				continue
			}
			last := len(fields) - 1
			if strings.EqualFold(fields[last], "no-resolve") {
				last--
			}
			if last < 1 {
				add("invalid_rule", "A rule has no policy target.", where)
				continue
			}
			target := fields[last]
			if strings.EqualFold(fields[0], "SUB-RULE") {
				if _, present := subRules[target]; !present {
					add("missing_sub_rule", "The rule references an absent sub-rule list.", where)
				} else if subName != "" {
					subGraph[subName] = append(subGraph[subName], target)
				}
			} else if known[target] == "" {
				add("dangling_rule_reference", "The rule references an absent proxy or group after the template overlay.", where)
			}
			if missingRuleProvider(fields, ruleProviders) {
				add("missing_rule_provider", "The rule references an absent rule-provider.", where)
			}
		}
	}
	checkRules(root["rules"], "rules", "")
	subNames := make([]string, 0, len(subRules))
	for name := range subRules {
		subNames = append(subNames, name)
	}
	sort.Strings(subNames)
	for i, name := range subNames {
		checkRules(subRules[name], fmt.Sprintf("sub-rules[%d]", i), name)
	}
	if hasReferenceCycle(subGraph) {
		add("sub_rule_cycle", "Sub-rule references contain a cycle.", "sub-rules")
	}
	return issues
}

func configProviders(root map[string]any, key string, issues *[]Issue) map[string]bool {
	names := map[string]bool{}
	if value, present := root[key]; present && value != nil {
		providers, valid := value.(map[string]any)
		if !valid {
			*issues = append(*issues, Issue{Code: "invalid_providers", Reason: "Provider definitions must be a mapping.", Path: key})
			return names
		}
		for name, value := range providers {
			if _, valid := value.(map[string]any); !valid || strings.TrimSpace(name) == "" {
				*issues = append(*issues, Issue{Code: "invalid_provider", Reason: "A provider must have a name and a mapping definition.", Path: key})
			} else {
				names[name] = true
			}
		}
	}
	return names
}

func hasReferenceCycle(graph map[string][]string) bool {
	state := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		if state[name] == 1 {
			return true
		}
		if state[name] == 2 {
			return false
		}
		state[name] = 1
		for _, ref := range graph[name] {
			if visit(ref) {
				return true
			}
		}
		state[name] = 2
		return false
	}
	for name := range graph {
		if visit(name) {
			return true
		}
	}
	return false
}

func splitRule(rule string) ([]string, bool) {
	depth, start := 0, 0
	parts := []string{}
	for i, r := range rule {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(rule[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	return append(parts, strings.TrimSpace(rule[start:])), true
}

func missingRuleProvider(fields []string, providers map[string]bool) bool {
	if len(fields) == 0 {
		return false
	}
	if strings.EqualFold(fields[0], "RULE-SET") {
		return len(fields) < 2 || !providers[fields[1]]
	}
	for _, field := range fields[1:] {
		if strings.HasPrefix(field, "(") && strings.HasSuffix(field, ")") {
			inner := field[1 : len(field)-1]
			parts, valid := splitRule(inner)
			if valid && missingRuleProvider(parts, providers) {
				return true
			}
		}
	}
	// Expressions can be lists of parenthesized rules without a type prefix.
	if strings.HasPrefix(fields[0], "(") && strings.HasSuffix(fields[0], ")") {
		inner := fields[0][1 : len(fields[0])-1]
		if parts, valid := splitRule(inner); valid && missingRuleProvider(parts, providers) {
			return true
		}
	}
	return false
}
