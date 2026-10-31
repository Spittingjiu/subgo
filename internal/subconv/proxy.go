package subconv

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
)

// convertProxy returns a supported mapping or an explicit fixed diagnostic.
// It never emits a partially populated proxy, nor returns net/url error text.
func convertProxy(raw string, idx int) (map[string]any, *Issue, []Issue) {
	p, issue := parseProxyURI(raw)
	if issue != nil {
		return nil, issue, nil
	}
	q := p.query
	if ambiguousQuery(q) {
		return nil, invalidURI("ambiguous_parameter", "Repeated connection parameters have conflicting values."), nil
	}
	name := p.name
	if name == "未命名节点" {
		name = "node-" + strconv.Itoa(idx)
	}
	m := map[string]any{"name": name, "server": p.host, "port": p.port, "udp": true}
	warnings := []Issue{}
	if p.scheme == "ss" {
		if !supportedCipher(p.cipher) {
			return nil, invalidURI("unsupported_ss_cipher", "The Shadowsocks cipher is not in the documented Mihomo cipher set."), nil
		}
		if p.password == "" && p.cipher != "none" {
			return nil, invalidURI("missing_password", "The node has no required authentication password."), nil
		}
		if strings.HasPrefix(p.cipher, "2022-") && !validSS2022Key(p.cipher, p.password) {
			return nil, invalidURI("invalid_ss_2022_key", "AEAD-2022 requires Base64 keys of the cipher's exact key length."), nil
		}
		m["type"], m["cipher"], m["password"] = "ss", p.cipher, p.password
		if plugin := q.Get("plugin"); plugin != "" {
			pluginName, opts, problem := shadowsocksPlugin(plugin)
			if problem != nil {
				return nil, problem, nil
			}
			m["plugin"], m["plugin-opts"] = pluginName, opts
		}
		warnings = append(warnings, ignoredQueryWarning(q, "plugin")...)
		return m, nil, warnings
	}
	if p.password == "" && p.scheme != "hy2" && p.scheme != "hysteria2" {
		return nil, invalidURI("missing_credentials", "The node has no required UUID or authentication password."), nil
	}
	sni, _, issue := queryAlias(q, "sni", "servername", "peer")
	if issue != nil {
		return nil, issue, nil
	}
	// Keep the existing no-SNI Host fallback for compatibility, but a supplied
	// TLS name NEVER overwrites the explicit WebSocket/XHTTP transport Host.
	sni = first(sni, q.Get("host"))
	insecure, hasInsecure, issue := queryBool(q, "insecure", "allowInsecure", "allowinsecure", "skip-cert-verify")
	if issue != nil {
		return nil, issue, nil
	}
	if hasInsecure {
		m["skip-cert-verify"] = insecure
		if insecure {
			warnings = append(warnings, Issue{Code: "insecure_tls", Reason: "The node explicitly disables TLS certificate verification."})
		}
	}
	if alpn := splitNonEmpty(q.Get("alpn"), ","); len(alpn) > 0 {
		m["alpn"] = alpn
	}
	if q.Get("fp") != "" {
		m["client-fingerprint"] = q.Get("fp")
	}
	if q.Get("ech") != "" {
		return nil, invalidURI("unsupported_ech_parameter", "ECH URI parameters require an explicit, version-compatible mapping and are not converted."), nil
	}

	switch p.scheme {
	case "vless", "trojan":
		network, _, issue := queryAlias(q, "type", "network", "transport")
		if issue != nil {
			return nil, issue, nil
		}
		network = strings.ToLower(first(network, "tcp"))
		security := strings.ToLower(q.Get("security"))
		if security == "" {
			if p.scheme == "trojan" {
				security = "tls" // Trojan is intrinsically TLS, not a toggle.
			} else {
				security = "none"
			}
		}
		if q.Get("pbk") != "" {
			if security != "none" && security != "tls" && security != "reality" {
				return nil, invalidURI("unsupported_security", "The requested TLS/security mode has no supported conversion."), nil
			}
			security = "reality"
		}
		if security != "none" && security != "tls" && security != "reality" {
			return nil, invalidURI("unsupported_security", "The requested TLS/security mode has no supported conversion."), nil
		}
		if tls, present, problem := queryBool(q, "tls"); problem != nil {
			return nil, problem, nil
		} else if present && tls != (security != "none") {
			return nil, invalidURI("conflicting_tls", "The URI contains conflicting TLS/security settings."), nil
		}
		if p.scheme == "trojan" && security == "none" {
			return nil, invalidURI("unsupported_trojan_plaintext", "Mihomo Trojan always uses TLS; a plaintext Trojan URI cannot be converted faithfully."), nil
		}
		if p.scheme == "trojan" && network != "tcp" && network != "ws" && network != "grpc" {
			return nil, invalidURI("unsupported_transport", "The transport is not supported by the documented Mihomo Trojan mapping."), nil
		}
		if p.scheme == "vless" {
			m["type"], m["uuid"] = "vless", p.password
			m["client-fingerprint"] = first(q.Get("fp"), "chrome")
			if security != "none" {
				m["tls"] = true
			}
			if sni != "" {
				m["servername"] = sni
			}
			if flow := q.Get("flow"); flow != "" {
				if network == "xhttp" {
					warnings = append(warnings, Issue{Code: "xhttp_flow_removed", Reason: "Flow is omitted for Mihomo XHTTP compatibility."})
				} else if flow != "xtls-rprx-vision" {
					return nil, invalidURI("unsupported_vless_flow", "The VLESS flow is not supported by the documented Mihomo mapping."), nil
				} else {
					m["flow"] = flow
				}
			}
			if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
				m["encryption"] = encryption
			}
		} else {
			m["type"], m["password"] = "trojan", p.password
			if sni != "" {
				m["sni"] = sni
			}
		}
		m["network"] = network
		transportWarnings, issue := applyTransport(m, p, network, sni)
		if issue != nil {
			return nil, issue, nil
		}
		warnings = append(warnings, transportWarnings...)
		if security == "reality" {
			key := strings.TrimSpace(q.Get("pbk"))
			if key == "" {
				return nil, invalidURI("missing_reality_public_key", "Reality requires a public key (pbk)."), nil
			}
			ro := map[string]any{"public-key": key}
			if q.Get("sid") != "" {
				ro["short-id"] = q.Get("sid")
			}
			if p.scheme == "vless" && network != "xhttp" {
				ro["spider-x"] = first(first(q.Get("spx"), q.Get("spiderx")), "/")
			}
			m["reality-opts"] = ro
		}
		if packet := q.Get("packetEncoding"); packet != "" {
			if p.scheme != "vless" || (packet != "xudp" && packet != "packetaddr") {
				return nil, invalidURI("unsupported_packet_encoding", "The requested UDP packet encoding is unsupported."), nil
			}
			m["packet-encoding"] = packet
		}
		warnings = append(warnings, ignoredQueryWarning(q, "sni", "servername", "peer", "host", "insecure", "allowInsecure", "allowinsecure", "skip-cert-verify", "alpn", "fp", "type", "network", "transport", "security", "tls", "pbk", "sid", "spx", "spiderx", "flow", "encryption", "path", "mode", "serviceName", "service-name", "service_name", "grpc-service-name", "headerType", "ed", "eh", "packetEncoding")...)
	case "hysteria2", "hy2":
		m["type"], m["password"] = "hysteria2", p.password
		if sni != "" {
			m["sni"] = sni
		}
		// fp is not a HY2 client fingerprint setting in Mihomo.
		delete(m, "client-fingerprint")
		if p.ports != "" {
			m["ports"] = p.ports
		}
		if ports := q.Get("mport"); ports != "" {
			if _, ok := validatePortSet(ports); !ok {
				return nil, invalidURI("invalid_ports", "The Hysteria 2 port hopping range is invalid."), nil
			}
			ports = strings.ReplaceAll(ports, ":", "-")
			if p.ports != "" && ports != p.ports {
				return nil, invalidURI("conflicting_ports", "The URI authority and query specify conflicting port hopping ranges."), nil
			}
			m["ports"] = ports
		}
		if interval := q.Get("mportInterval"); interval != "" {
			seconds, err := strconv.Atoi(interval)
			if err != nil || seconds < 5 {
				return nil, invalidURI("invalid_hop_interval", "Mihomo Hysteria 2 requires a port hop interval of at least five seconds."), nil
			}
			m["hop-interval"] = seconds
		}
		obfs := strings.ToLower(q.Get("obfs"))
		if obfs != "" {
			// Latest docs include gecko, but the verified compatibility target
			// Mihomo v1.19.24 rejects it. Do not silently change the obfuscator.
			if obfs == "gecko" {
				return nil, invalidURI("unsupported_hy2_obfs_version", "HY2 gecko is unsupported by the verified Mihomo v1.19.24 compatibility target; a newer core with verified gecko support is required."), nil
			}
			if obfs != "salamander" {
				return nil, invalidURI("unsupported_hy2_obfs", "The Hysteria 2 obfuscation type is unsupported."), nil
			}
			if q.Get("obfs-password") == "" {
				return nil, invalidURI("missing_obfs_password", "Hysteria 2 obfuscation requires an obfuscation password."), nil
			}
			m["obfs"], m["obfs-password"] = obfs, q.Get("obfs-password")
		} else if q.Get("obfs-password") != "" {
			return nil, invalidURI("missing_obfs_type", "An obfuscation password without an obfuscation type is ambiguous."), nil
		}
		if pin := q.Get("pinSHA256"); pin != "" {
			fingerprint := strings.ReplaceAll(pin, ":", "")
			bytes, err := hex.DecodeString(fingerprint)
			if err != nil || len(bytes) != 32 {
				return nil, invalidURI("invalid_certificate_pin", "The TLS SHA-256 pin must contain exactly 32 hexadecimal bytes."), nil
			}
			m["fingerprint"] = fingerprint
		}
		warnings = append(warnings, ignoredQueryWarning(q, "sni", "servername", "peer", "host", "insecure", "allowInsecure", "allowinsecure", "skip-cert-verify", "alpn", "obfs", "obfs-password", "mport", "mportInterval", "pinSHA256")...)
	case "anytls":
		m["type"], m["password"] = "anytls", p.password
		if sni != "" {
			m["sni"] = sni
		}
		warnings = append(warnings, ignoredQueryWarning(q, "sni", "servername", "peer", "host", "insecure", "allowInsecure", "allowinsecure", "skip-cert-verify", "alpn", "fp")...)
	}
	return m, nil, warnings
}

func applyTransport(m map[string]any, p proxyURI, network, sni string) ([]Issue, *Issue) {
	q := p.query
	warnings := []Issue{}
	switch network {
	case "tcp":
		if header := q.Get("headerType"); header != "" && header != "none" {
			return nil, invalidURI("unsupported_tcp_header", "TCP header obfuscation requires a separate explicit mapping and is not converted.")
		}
	case "ws":
		m["ws-opts"] = map[string]any{
			"path":    first(q.Get("path"), "/"),
			"headers": map[string]any{"Host": first(q.Get("host"), p.host)},
		}
		if early := q.Get("ed"); early != "" {
			v, err := strconv.Atoi(early)
			if err != nil || v < 0 {
				return nil, invalidURI("invalid_ws_early_data", "WebSocket early-data size must be a non-negative integer.")
			}
			m["ws-opts"].(map[string]any)["max-early-data"] = v
		}
		if header := q.Get("eh"); header != "" {
			m["ws-opts"].(map[string]any)["early-data-header-name"] = header
		}
	case "grpc":
		service, _, issue := queryAlias(q, "serviceName", "service-name", "service_name", "grpc-service-name")
		if issue != nil {
			return nil, issue
		}
		if mode := q.Get("mode"); mode != "" && mode != "gun" {
			return nil, invalidURI("unsupported_grpc_mode", "The requested gRPC mode has no faithful Mihomo mapping.")
		}
		m["grpc-opts"] = map[string]any{"grpc-service-name": service}
		if service == "" {
			warnings = append(warnings, Issue{Code: "grpc_default_service_name", Reason: "The URI does not specify a gRPC service name; the empty service name is retained."})
		}
	case "http":
		opts := map[string]any{"path": []string{first(q.Get("path"), "/")}}
		if q.Get("host") != "" {
			opts["headers"] = map[string]any{"Host": splitNonEmpty(q.Get("host"), ",")}
		}
		m["http-opts"] = opts
	case "h2":
		opts := map[string]any{"path": first(q.Get("path"), "/")}
		if hosts := splitNonEmpty(q.Get("host"), ","); len(hosts) > 0 {
			opts["host"] = hosts
		}
		m["h2-opts"] = opts
	case "xhttp":
		// Retain the already-proven Reality XHTTP Host/SNI separation, flow
		// removal and omission of mode=auto for the deployed Mihomo version.
		opts := map[string]any{"path": first(q.Get("path"), "/")}
		if host := first(q.Get("host"), sni); host != "" {
			opts["host"] = host
		}
		if mode := strings.TrimSpace(q.Get("mode")); mode != "" {
			switch mode {
			case "stream-one", "stream-up", "packet-up":
				opts["mode"] = mode
			case "auto":
				warnings = append(warnings, Issue{Code: "xhttp_auto_mode_defaulted", Reason: "XHTTP auto mode is omitted for compatibility with the deployed Mihomo version."})
			default:
				return nil, invalidURI("unsupported_xhttp_mode", "The XHTTP mode is unsupported by the compatible Mihomo mapping.")
			}
		}
		if q.Get("extra") != "" {
			return nil, invalidURI("unsupported_xhttp_extra", "XHTTP extra/download settings have no verified URI mapping and are not converted.")
		}
		m["xhttp-opts"] = opts
	default:
		return nil, invalidURI("unsupported_transport", "The transport has no supported Mihomo URI conversion.")
	}
	return warnings, nil
}

func ignoredQueryWarning(q url.Values, handled ...string) []Issue {
	known := make(map[string]bool, len(handled))
	for _, key := range handled {
		known[key] = true
	}
	for key := range q {
		if !known[key] {
			return []Issue{{Code: "ignored_uri_parameters", Reason: "The URI contains additional parameters that are not mapped; inspect the upstream protocol settings before use."}}
		}
	}
	return nil
}

func supportedCipher(cipher string) bool {
	for _, value := range strings.Fields("aes-128-ctr aes-192-ctr aes-256-ctr aes-128-cfb aes-192-cfb aes-256-cfb aes-128-gcm aes-192-gcm aes-256-gcm aes-128-ccm aes-192-ccm aes-256-ccm aes-128-gcm-siv aes-256-gcm-siv chacha20-ietf chacha20 xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305 chacha8-ietf-poly1305 xchacha8-ietf-poly1305 2022-blake3-aes-128-gcm 2022-blake3-aes-256-gcm 2022-blake3-chacha20-poly1305 lea-128-gcm lea-192-gcm lea-256-gcm rabbit128-poly1305 aegis-128l aegis-256 aez-384 deoxys-ii-256-128 rc4-md5 none") {
		if cipher == value {
			return true
		}
	}
	return false
}

func validSS2022Key(cipher, password string) bool {
	length := 32
	if cipher == "2022-blake3-aes-128-gcm" {
		length = 16
	}
	for _, key := range strings.Split(password, ":") {
		data, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(data) != length {
			return false
		}
	}
	return true
}

// SIP002 plugin options use backslash escaping for literal delimiters. Unknown
// plugins/options are refused, never silently discarded or executed externally.
func shadowsocksPlugin(raw string) (string, map[string]any, *Issue) {
	tokens, ok := splitEscaped(raw, ';')
	if !ok || len(tokens) == 0 || tokens[0] == "" {
		return "", nil, invalidURI("invalid_ss_plugin", "The SIP002 plugin arguments are malformed.")
	}
	name, ok := unescapePlugin(tokens[0])
	if !ok {
		return "", nil, invalidURI("invalid_ss_plugin", "The SIP002 plugin arguments have invalid escaping.")
	}
	values := map[string]string{}
	for _, token := range tokens[1:] {
		parts, valid := splitEscaped(token, '=')
		if !valid || len(parts) > 2 || parts[0] == "" {
			return "", nil, invalidURI("invalid_ss_plugin", "The SIP002 plugin option delimiters are malformed.")
		}
		key, valid := unescapePlugin(parts[0])
		value := "true" // SIP003 plugin flags, such as tls.
		if len(parts) == 2 {
			value, ok = unescapePlugin(parts[1])
			valid = valid && ok
		}
		if !valid {
			return "", nil, invalidURI("invalid_ss_plugin", "The SIP002 plugin option has invalid escaping.")
		}
		if old, exists := values[key]; exists && old != value {
			return "", nil, invalidURI("ambiguous_ss_plugin", "Repeated SIP002 plugin options have conflicting values.")
		}
		values[key] = value
	}
	opts := map[string]any{}
	switch strings.ToLower(name) {
	case "obfs-local", "simple-obfs", "obfs":
		for key := range values {
			if key != "obfs" && key != "obfs-host" {
				return "", nil, invalidURI("unsupported_ss_plugin_option", "The simple-obfs URI includes an option without a verified Mihomo mapping.")
			}
		}
		mode := values["obfs"]
		if mode != "http" && mode != "tls" {
			return "", nil, invalidURI("unsupported_ss_plugin_mode", "Simple-obfs requires obfs=http or obfs=tls.")
		}
		opts["mode"] = mode
		if values["obfs-host"] != "" {
			opts["host"] = values["obfs-host"]
		}
		return "obfs", opts, nil
	case "v2ray-plugin":
		for key := range values {
			if key != "mode" && key != "tls" && key != "mux" && key != "host" && key != "path" {
				return "", nil, invalidURI("unsupported_ss_plugin_option", "The v2ray-plugin URI includes an option without a verified Mihomo mapping.")
			}
		}
		if mode := values["mode"]; mode != "" && mode != "websocket" {
			return "", nil, invalidURI("unsupported_ss_plugin_mode", "Mihomo v2ray-plugin supports WebSocket, not QUIC or server mode.")
		}
		opts["mode"] = "websocket"
		for _, key := range []string{"tls", "mux"} {
			if value, present := values[key]; present {
				v, err := strconv.ParseBool(value)
				if err != nil {
					return "", nil, invalidURI("invalid_ss_plugin_boolean", "A SIP002 plugin flag must be true/false or 1/0.")
				}
				opts[key] = v
			}
		}
		for _, key := range []string{"host", "path"} {
			if value, present := values[key]; present {
				opts[key] = value
			}
		}
		return "v2ray-plugin", opts, nil
	default:
		return "", nil, invalidURI("unsupported_ss_plugin", "The SIP002 plugin has no verified Mihomo URI mapping.")
	}
}

func splitEscaped(raw string, delimiter byte) ([]string, bool) {
	parts := []string{}
	var value strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			if i+1 == len(raw) {
				return nil, false
			}
			value.WriteByte(raw[i])
			i++
			value.WriteByte(raw[i])
		} else if raw[i] == delimiter {
			parts = append(parts, value.String())
			value.Reset()
		} else {
			value.WriteByte(raw[i])
		}
	}
	return append(parts, value.String()), true
}

func unescapePlugin(raw string) (string, bool) {
	var value strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			i++
			if i == len(raw) || !strings.ContainsRune(":;=\\", rune(raw[i])) {
				return "", false
			}
		}
		value.WriteByte(raw[i])
	}
	return value.String(), true
}
