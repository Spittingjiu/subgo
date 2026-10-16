package logs

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Spittingjiu/subgo/internal/db"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	svc := New(d.DB)
	t.Cleanup(svc.Stop)
	return svc
}

func insertSubscriptionLog(t *testing.T, svc *Service, ua string) {
	t.Helper()
	if _, err := svc.db.Exec(`INSERT INTO subscription_logs(token,subscription_id,subscription_name,route_type,client_ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?)`,
		"tok-1", 3, "朋友的订阅", "clash", "203.0.113.9", ua, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert subscription_logs: %v", err)
	}
}

func TestWritePersistsQueuedLinesNewestFirst(t *testing.T) {
	svc := newTestService(t)
	svc.Info("app", "服务启动")
	svc.Warn("sync", "上游响应很慢")
	svc.Error("template", "模板被拒绝")
	svc.Stop()

	rows, total, err := svc.System(Filter{})
	if err != nil {
		t.Fatalf("System: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("want 3 rows, got total=%d len=%d", total, len(rows))
	}
	if rows[0].Message != "模板被拒绝" || rows[0].Level != "error" || rows[0].Scope != "template" {
		t.Errorf("newest row wrong: %+v", rows[0])
	}
	if rows[2].Message != "服务启动" || rows[2].Level != "info" {
		t.Errorf("oldest row wrong: %+v", rows[2])
	}
}

func TestWriteIgnoresBlankMessagesAndLateWritesAreSafe(t *testing.T) {
	svc := newTestService(t)
	svc.Info("app", "   ")
	svc.Stop()
	// A line emitted while shutting down must not panic on a closed channel.
	svc.Info("app", "shutdown")
	if _, total, _ := svc.System(Filter{}); total != 0 {
		t.Fatalf("blank message should be dropped, got %d rows", total)
	}
}

func TestSinkParsesProcessLogLines(t *testing.T) {
	svc := newTestService(t)
	sink := svc.Sink()
	line := []byte("2026/10/17 01:02:03 [clash-template] rejected invalid template, keeping previous version\n")
	if n, err := sink.Write(line); n != len(line) || err != nil {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(line))
	}
	_, _ = sink.Write([]byte("[source-sync] manual results=map[1:ok]\n"))
	svc.Stop()

	rows, total, err := svc.System(Filter{})
	if err != nil {
		t.Fatalf("System: %v", err)
	}
	if total != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", total, rows)
	}
	byScope := map[string]SystemRow{}
	for _, r := range rows {
		byScope[r.Scope] = r
	}
	tpl, ok := byScope["template"]
	if !ok {
		t.Fatalf("[clash-template] should be filed under the template scope, got %+v", rows)
	}
	if tpl.Level != "error" {
		t.Errorf("a rejected template should be an error, got %q", tpl.Level)
	}
	if strings.Contains(tpl.Message, "2026/10/17") {
		t.Errorf("the journald timestamp should be stripped, got %q", tpl.Message)
	}
	if _, ok := byScope["sync"]; !ok {
		t.Errorf("[source-sync] should be filed under the sync scope, got %+v", rows)
	}
}

func TestSystemFilterAndSearch(t *testing.T) {
	svc := newTestService(t)
	svc.Info("app", "服务启动")
	svc.Error("template", "template rejected")
	svc.Stop()

	for _, tc := range []struct {
		name string
		f    Filter
		want int
	}{
		{"scope", Filter{Scope: "template"}, 1},
		{"level", Filter{Level: "error"}, 1},
		{"query ascii", Filter{Q: "rejected"}, 1},
		{"query chinese", Filter{Q: "服务"}, 1},
		{"scope and level", Filter{Scope: "template", Level: "info"}, 0},
	} {
		rows, total, err := svc.System(tc.f)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if total != tc.want || len(rows) != tc.want {
			t.Errorf("%s: got total=%d len=%d, want %d", tc.name, total, len(rows), tc.want)
		}
		if rows == nil {
			t.Errorf("%s: rows must be an empty slice so the API answers [] and not null", tc.name)
		}
	}
}

func TestSubscriptionsAnnotateDeviceAndFilter(t *testing.T) {
	svc := newTestService(t)
	insertSubscriptionLog(t, svc, "Clash Verge/1.7.7 (Windows)")

	rows, total, err := svc.Subscriptions(Filter{})
	if err != nil {
		t.Fatalf("Subscriptions: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("want 1 row, got total=%d len=%d", total, len(rows))
	}
	if rows[0].Device != "Clash Verge · Windows" {
		t.Errorf("device = %q", rows[0].Device)
	}
	if rows[0].Icon != "🪟" {
		t.Errorf("icon = %q", rows[0].Icon)
	}
	if rows[0].RouteType != "clash" {
		t.Errorf("route type = %q", rows[0].RouteType)
	}
	if _, total, _ := svc.Subscriptions(Filter{Q: "朋友"}); total != 1 {
		t.Error("search by subscription name should match")
	}
	if _, total, _ := svc.Subscriptions(Filter{Q: "203.0.113"}); total != 1 {
		t.Error("search by client ip should match")
	}
	if _, total, _ := svc.Subscriptions(Filter{SubscriptionID: 4}); total != 0 {
		t.Error("subscription filter should be applied")
	}
}

func TestPruneAndClear(t *testing.T) {
	svc := newTestService(t)
	old := time.Now().UTC().AddDate(0, 0, -40).Format(time.RFC3339)
	if _, err := svc.db.Exec(`INSERT INTO system_logs(level,scope,message,detail,created_at) VALUES(?,?,?,?,?)`, "info", "app", "old", "", old); err != nil {
		t.Fatalf("insert system_logs: %v", err)
	}
	svc.Info("app", "fresh")
	svc.Stop()

	removed, err := svc.Prune(30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Errorf("Prune removed %d rows, want 1", removed)
	}
	if _, total, _ := svc.System(Filter{}); total != 1 {
		t.Error("the fresh row should survive the prune")
	}
	if removed, err := svc.Prune(0); err != nil || removed != 0 {
		t.Errorf("Prune(0) = (%d, %v), want (0, nil)", removed, err)
	}
	if removed, err := svc.Clear(KindSystem); err != nil || removed != 1 {
		t.Errorf("Clear = (%d, %v), want (1, nil)", removed, err)
	}
	if _, err := svc.Clear("nope"); err == nil {
		t.Error("Clear must reject an unknown kind instead of guessing a table")
	}
}

func TestScopesAndStats(t *testing.T) {
	svc := newTestService(t)
	svc.Info("app", "one")
	svc.Info("app", "two")
	svc.Info("sync", "three")
	insertSubscriptionLog(t, svc, "Clash Verge/1.7.7 (Windows)")
	if _, err := svc.db.Exec(`INSERT INTO audit_logs(action,target_type,target_id,detail,created_at) VALUES(?,?,?,?,?)`, "新增订阅", "订阅", "3", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert audit_logs: %v", err)
	}
	svc.Stop()

	scopes, err := svc.Scopes()
	if err != nil {
		t.Fatalf("Scopes: %v", err)
	}
	if len(scopes) != 2 || scopes[0].Scope != "app" || scopes[0].Count != 2 {
		t.Fatalf("Scopes = %+v", scopes)
	}
	st, err := svc.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.System != 3 || st.Subscription != 1 || st.Audit != 1 {
		t.Errorf("Stats = %+v", st)
	}
	audits, total, err := svc.Audits(Filter{Q: "新增"})
	if err != nil || total != 1 || len(audits) != 1 || audits[0].TargetType != "订阅" {
		t.Errorf("Audits = (%+v, %d, %v)", audits, total, err)
	}
}

func TestExportWritesCSVWithBOM(t *testing.T) {
	svc := newTestService(t)
	svc.Error("template", `模板里有 "引号" 和, 逗号`)
	svc.Stop()

	var buf bytes.Buffer
	if err := svc.Export(KindSystem, Filter{}, &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "\ufeff") {
		t.Error("the CSV should start with a BOM so Excel reads it as UTF-8")
	}
	if !strings.Contains(out, "时间,级别,模块,内容,详情") {
		t.Errorf("missing header row: %q", out)
	}
	if !strings.Contains(out, `"模板里有 ""引号"" 和, 逗号"`) {
		t.Errorf("value was not CSV-quoted: %q", out)
	}
	if err := svc.Export("nope", Filter{}, &buf); err == nil {
		t.Error("Export must reject an unknown kind")
	}
}

func TestDeviceLabel(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"clash-verge/v2.4.2", "Clash Verge"},
		{"Clash Verge/1.7.7 (Windows)", "Clash Verge · Windows"},
		{"ClashforWindows/0.20.39", "Clash for Windows"},
		{"ClashX/1.118.0", "ClashX"},
		{"Clash.Meta/v1.18.0", "Clash.Meta"},
		{"FlClash/0.8.70", "FlClash"},
		{"Stash/2.5.0", "Stash"},
		{"Hiddify/2.0.0 (Android 14)", "Hiddify · Android"},
		{"sing-box 1.8.0", "sing-box"},
		{"SFA/1.8.0 (iPhone; iOS 17.0)", "sing-box · iPhone"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "浏览器 · iPhone"},
		{"curl/8.5.0", "命令行"},
		{"Go-http-client/1.1", ""},
	} {
		if got := DeviceLabel(tc.ua); got != tc.want {
			t.Errorf("DeviceLabel(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestDeviceIcon(t *testing.T) {
	for _, tc := range []struct{ device, want string }{
		{"Clash Verge · Windows", "🪟"},
		{"Shadowrocket · iPhone", "🍎"},
		{"Hiddify · Android", "🤖"},
		{"sing-box · Linux", "🐧"},
		{"命令行", "💻"},
		{"", "🌐"},
	} {
		if got := DeviceIcon(tc.device); got != tc.want {
			t.Errorf("DeviceIcon(%q) = %q, want %q", tc.device, got, tc.want)
		}
	}
}
