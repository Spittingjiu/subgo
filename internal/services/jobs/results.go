package jobs

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/services/connectivity"
	"github.com/Spittingjiu/subgo/internal/services/source"
)

func syncResult(id int64, err error) Result {
	r := Result{SourceID: id, Status: "ok", Code: "ok", Message: "source synchronized"}
	if err == nil {
		return r
	}
	r.Status = "fail"
	switch {
	case errors.Is(err, context.Canceled):
		r.Status, r.Code, r.Message = "cancelled", "cancelled", "source synchronization cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		r.Code, r.Message = "timeout", "source synchronization timed out"
	case errors.Is(err, source.ErrSyncInProgress):
		r.Code, r.Message = "source_busy", "source already being synchronized"
	case errors.Is(err, source.ErrSourceDisabled):
		r.Status, r.Code, r.Message = "skipped", "source_disabled", "source was disabled before execution"
	case errors.Is(err, source.ErrEmptyFetch):
		r.Code, r.Message = "source_empty", "upstream returned no links; existing nodes retained"
	case errors.Is(err, sql.ErrNoRows):
		r.Status, r.Code, r.Message = "skipped", "source_removed", "source no longer exists"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			r.Code, r.Message = "timeout", "source request timed out"
		} else if strings.Contains(err.Error(), "HTTP ") {
			r.Code, r.Message = "source_http", "upstream HTTP request was rejected"
		} else if strings.Contains(err.Error(), "unsupported source type") {
			r.Code, r.Message = "source_unsupported", "source type is unsupported"
		} else {
			r.Code, r.Message = "source_failed", "source synchronization failed"
		}
	}
	if r.Status == "fail" {
		r.Error = r.Message
	}
	return r
}

// Only known classifications reach the task API. In particular, never store
// a kernel stderr line, url.Error, server-selected name or arbitrary LastError.
func connectivityResult(result connectivity.Result) Result {
	r := Result{NodeID: result.NodeID, Status: result.Status, Code: result.Code, ElapsedMS: result.ElapsedMS}
	if r.ElapsedMS < 0 {
		r.ElapsedMS = 0
	}
	if _, err := time.Parse(time.RFC3339Nano, result.CheckedAt); err == nil {
		r.CheckedAt = result.CheckedAt
	} else {
		r.CheckedAt = timestamp()
	}
	if result.LatencyMS != nil && *result.LatencyMS >= 0 {
		lat := *result.LatencyMS
		r.LatencyMS = &lat
	}
	switch r.Status {
	case "ok", "fail", "unknown", "cancelled", "skipped":
	default:
		r.Status = "unknown"
	}
	switch r.Code {
	case "ok":
		r.Message = "node reachable through the proxy"
	case "cancelled":
		r.Status, r.Message = "cancelled", "node check cancelled"
	case "stale", "stale_link", "stale_result", "link_changed", "target_changed":
		r.Code, r.Status, r.Message = "stale_link", "skipped", "link changed during the check; old result discarded"
	case "scope_changed", "node_disabled", "source_disabled", "node_missing", "node_removed", "ineligible":
		r.Code, r.Status, r.Message = "scope_changed", "skipped", "node is no longer eligible; result discarded"
	case "kernel_missing", "kernel_unavailable", "kernel_not_installed":
		r.Code, r.Message = "kernel_missing", "connectivity kernel is not installed"
	case "config_invalid", "invalid_config", "config_rejected", "config_timeout":
		r.Code, r.Message = "config_invalid", "connectivity kernel rejected the generated configuration"
	case "unsupported", "invalid_link", "unsupported_link", "unsupported_proxy", "malformed_link":
		r.Code, r.Message = "unsupported", "node cannot be converted to a supported check configuration"
	case "temp_dir", "config_write", "local_io", "config_write_failed", "temp_dir_failed", "temp_cleanup_failed", "local_port_unavailable":
		r.Code, r.Message = "local_io", "local check workspace could not be prepared"
	case "kernel_start", "kernel_unready", "kernel_exit", "kernel_error", "start_failed", "proxy_not_ready", "kernel_start_failed", "kernel_exited", "kernel_timeout", "local_proxy_unavailable", "local_proxy_auth_failed":
		r.Code, r.Message = "kernel_error", "local connectivity kernel did not become ready"
	case "timeout", "proxy_timeout", "network_timeout", "remote_timeout":
		r.Code, r.Message = "timeout", "proxy request timed out"
	case "proxy_error", "remote_error", "network", "network_error", "proxy_network":
		r.Code, r.Message = "proxy_error", "request through the proxy failed"
	case "target_tls", "tls_error", "target_tls_failed":
		r.Code, r.Message = "target_tls", "check target TLS could not be verified"
	case "target_http", "target_response", "unexpected_status", "target_invalid", "target_status_unexpected":
		r.Code, r.Message = "target_http", "check target did not return the expected HTTP 204"
	case "save_failed", "storage_error", "storage_failed":
		r.Code, r.Message = "storage_error", "connectivity result could not be stored"
	default:
		if r.Status == "ok" {
			r.Code, r.Message = "ok", "node reachable through the proxy"
		} else {
			r.Code, r.Message = "connectivity_failed", "connectivity check was inconclusive"
		}
	}
	if r.Status == "fail" || r.Status == "unknown" {
		r.Error = r.Message
	}
	return r
}
