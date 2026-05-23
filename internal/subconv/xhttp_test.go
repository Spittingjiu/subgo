package subconv

import "testing"

func TestVLESSXHTTPRealityKeepsFlowAndDropsInvalidAutoMode(t *testing.T) {
	raw := "vless://580e2d06-ef53-4be4-82fe-92309c3ff0dd@161.118.254.193:20000?flow=xtls-rprx-vision&fp=chrome&host=www.icloud.com&mode=auto&path=%2F&pbk=dRC0nXMl5dCQoJZVg9Hwtc9ulDEoe9Dgijtv-DJXUWo&security=reality&sid=5d65e5ff&sni=www.icloud.com&type=xhttp#SG"
	p := ClashProxy(raw)
	if p["flow"] != "xtls-rprx-vision" {
		t.Fatalf("expected flow to be preserved for xhttp reality, got %#v", p["flow"])
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
