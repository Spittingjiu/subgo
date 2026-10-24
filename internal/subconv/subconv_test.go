package subconv

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStableHashIgnoresFragment(t *testing.T) {
	a := "vless://uuid@example.com:443?security=reality&pbk=abc#old-name"
	b := "vless://uuid@example.com:443?security=reality&pbk=abc#new-name"
	if StableHash(a) != StableHash(b) {
		t.Fatalf("StableHash should ignore URL fragment/display name")
	}
}

func TestStableHashKeepsConnectionParams(t *testing.T) {
	a := "vless://uuid@example.com:443?security=reality&pbk=abc#name"
	b := "vless://uuid@example.com:443?security=reality&pbk=def#name"
	if StableHash(a) == StableHash(b) {
		t.Fatalf("StableHash should include connection parameters")
	}
}

func TestValidateTemplateRejectsBrokenYAML(t *testing.T) {
	// A single stray space in front of a dns key once made a whole template
	// unparseable, which silently dropped every policy group from subscriptions.
	broken := []byte("dns:\n  enable: true\n\n   proxy-server-nameserver-policy:\n    \"geosite:cn\":\n      - 223.5.5.5\n")
	if _, err := ValidateTemplate(broken); err == nil {
		t.Fatalf("ValidateTemplate should reject a template that is not valid YAML")
	}
}

func TestValidateTemplateAcceptsUsableTemplate(t *testing.T) {
	good := []byte("mixed-port: 7890\nproxy-groups:\n  - name: 节点选择\n    type: select\n    proxies:\n      - DIRECT\nrules:\n  - MATCH,节点选择\n")
	info, err := ValidateTemplate(good)
	if err != nil {
		t.Fatalf("ValidateTemplate rejected a valid template: %v", err)
	}
	if info.ProxyGroups != 1 || info.Rules != 1 {
		t.Fatalf("unexpected template info: %+v", info)
	}
}

func TestBuiltInTemplateKeepsCNTrafficDirect(t *testing.T) {
	links := []string{"vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&pbk=abc#node-1"}
	out, err := ClashYAML(links)
	if err != nil {
		t.Fatalf("ClashYAML failed: %v", err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("generated config is not valid yaml: %v", err)
	}
	if allowLan, _ := cfg["allow-lan"].(bool); allowLan {
		t.Fatalf("built-in template must not enable allow-lan")
	}
	if _, ok := cfg["dns"]; !ok {
		t.Fatalf("built-in template should ship a dns section")
	}
	rawRules, _ := cfg["rules"].([]any)
	rules := make([]string, 0, len(rawRules))
	for _, r := range rawRules {
		rules = append(rules, fmt.Sprint(r))
	}
	joined := strings.Join(rules, "\n")
	for _, want := range []string{"DOMAIN-SUFFIX,qpic.cn,DIRECT", "GEOSITE,cn,DIRECT", "MATCH,🚀 节点选择"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("built-in template is missing %q; rules were:\n%s", want, joined)
		}
	}
}

func TestClashProxyAnyTLS(t *testing.T) {
	raw := "anytls://secretpass@hk.example.com:12612?insecure=1&sni=www.bing.com#HK-AnyTLS"
	px := ClashProxy(raw)
	if px == nil {
		t.Fatalf("anytls must not be dropped")
	}
	if px["type"] != "anytls" {
		t.Fatalf("wrong type: %v", px["type"])
	}
	if px["password"] != "secretpass" {
		t.Fatalf("wrong password: %v", px["password"])
	}
	if px["server"] != "hk.example.com" || px["port"] != 12612 {
		t.Fatalf("wrong endpoint: %v:%v", px["server"], px["port"])
	}
	if px["sni"] != "www.bing.com" {
		t.Fatalf("wrong sni: %v", px["sni"])
	}
	if px["skip-cert-verify"] != true {
		t.Fatalf("insecure=1 must map to skip-cert-verify")
	}
	if px["name"] != "HK-AnyTLS" {
		t.Fatalf("wrong name: %v", px["name"])
	}
}

func TestClashYAMLIncludesAnyTLS(t *testing.T) {
	links := []string{
		"anytls://secretpass@hk.example.com:12612?insecure=1&sni=www.bing.com#HK-AnyTLS",
	}
	out, err := ClashYAML(links)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "type: anytls") {
		t.Fatalf("clash config missing anytls proxy:\n%s", out)
	}
	if !strings.Contains(out, "HK-AnyTLS") {
		t.Fatalf("clash config missing node name:\n%s", out)
	}
}
