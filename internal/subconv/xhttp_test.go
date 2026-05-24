package subconv

import "testing"

func TestVLESSXHTTPRealityDropsFlowAndInvalidAutoMode(t *testing.T) {
	raw := "vless://580e2d06-ef53-4be4-82fe-92309c3ff0dd@161.118.254.193:20000?flow=xtls-rprx-vision&fp=chrome&host=www.icloud.com&mode=auto&path=%2F&pbk=dRC0nXMl5dCQoJZVg9Hwtc9ulDEoe9Dgijtv-DJXUWo&security=reality&sid=5d65e5ff&sni=www.icloud.com&type=xhttp#SG"
	p := ClashProxy(raw)
	if _, ok := p["flow"]; ok {
		t.Fatalf("xhttp should not emit flow for Mihomo compatibility, got %#v", p["flow"])
	}
	xopts, ok := p["xhttp-opts"].(map[string]any)
	if !ok {
		t.Fatalf("missing xhttp-opts: %#v", p)
	}
	if _, ok := xopts["mode"]; ok {
		t.Fatalf("mode=auto should be omitted for Mihomo compatibility: %#v", xopts)
	}
}

func TestVLESSXHTTPKeepsValidMode(t *testing.T) {
	raw := "vless://uuid@example.com:443?type=xhttp&security=tls&mode=stream-one&path=%2Fx#n"
	p := ClashProxy(raw)
	xopts := p["xhttp-opts"].(map[string]any)
	if xopts["mode"] != "stream-one" {
		t.Fatalf("expected valid xhttp mode to be preserved, got %#v", xopts["mode"])
	}
}

func TestVLESSXHTTPPrefersExplicitHostOverSNI(t *testing.T) {
	raw := "vless://5fd76956-639c-4801-b6e3-235f22d449f4@45.143.130.90:35832?type=xhttp&path=%2F&host=45.143.130.90&security=reality&sni=www.apple.com&pbk=yLNyOGFSI1ZnFNT8W8BfpB5TdQQHNPhXpXFdgyXMVhM&sid=f7da5bdb6eb35aea&flow=xtls-rprx-vision&fp=chrome#xhttpsjc"
	p := ClashProxy(raw)
	xopts := p["xhttp-opts"].(map[string]any)
	if xopts["host"] != "45.143.130.90" {
		t.Fatalf("expected explicit xhttp host to be preserved, got %#v", xopts["host"])
	}
	if p["servername"] != "www.apple.com" {
		t.Fatalf("expected SNI/servername to remain www.apple.com, got %#v", p["servername"])
	}
}

func TestVLESSXHTTPDoesNotEmitFlow(t *testing.T) {
	raw := "vless://580e2d06-ef53-4be4-82fe-92309c3ff0dd@161.118.254.193:20000?flow=xtls-rprx-vision&fp=chrome&host=www.icloud.com&mode=auto&path=%2F&pbk=dRC0nXMl5dCQoJZVg9Hwtc9ulDEoe9Dgijtv-DJXUWo&security=reality&sid=5d65e5ff&sni=www.icloud.com&type=xhttp#SG"
	p := ClashProxy(raw)
	if _, ok := p["flow"]; ok {
		t.Fatalf("xhttp should not emit flow, got %#v", p["flow"])
	}
}
