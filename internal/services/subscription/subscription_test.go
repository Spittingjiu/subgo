package subscription

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Spittingjiu/subgo/internal/db"
)

const testLink = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?flow=xtls-rprx-vision&fp=chrome&security=reality&pbk=AAA&sid=bb&type=tcp#test-node"

func newTestService(t *testing.T) (*Service, *db.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "subscriptions.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := d.Exec(`INSERT INTO nodes(source_id,display_no,node_hash,raw_link,node_name,protocol,enabled,created_at,updated_at) VALUES(1,?,?,?,?,?,1,?,?)`,
		"L-001", "hash-1", testLink, "test-node", "vless", now, now); err != nil {
		t.Fatalf("insert node: %v", err)
	}
	return New(d.DB), d
}

// TestFetchRecordsRouteType pins what 访问日志 reports: a Clash client must not be
// logged as a plain one, otherwise the log cannot be used to tell them apart.
func TestFetchRecordsRouteType(t *testing.T) {
	svc, d := newTestService(t)
	sub, err := svc.Create("测试订阅", []string{"hash-1"}, nil, false)
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := svc.PlainLinks(sub.Token, "203.0.113.9", "Shadowrocket/2.2.4"); err != nil {
		t.Fatalf("PlainLinks: %v", err)
	}
	if _, err := svc.Clash(sub.Token, "203.0.113.9", "Clash Verge/1.7.7", nil); err != nil {
		t.Fatalf("Clash: %v", err)
	}

	rows, err := d.Query(`SELECT route_type, client_ip, user_agent FROM subscription_logs ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("query logs: %v", err)
	}
	defer rows.Close()
	var got []string
	var ips []string
	for rows.Next() {
		var route, ip, ua string
		if err := rows.Scan(&route, &ip, &ua); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, route)
		ips = append(ips, ip)
	}
	if len(got) != 2 || got[0] != "plain" || got[1] != "clash" {
		t.Fatalf("route types = %v, want [plain clash]", got)
	}
	for i, ip := range ips {
		if ip != "203.0.113.9" {
			t.Errorf("row %d client ip = %q", i, ip)
		}
	}

	var count int64
	if err := d.QueryRow(`SELECT access_count FROM subscriptions WHERE id=?`, sub.ID).Scan(&count); err != nil {
		t.Fatalf("read access_count: %v", err)
	}
	if count != 2 {
		t.Errorf("access_count = %d, want 2", count)
	}
}

func TestPlainLinksRejectsDisabledSubscription(t *testing.T) {
	svc, d := newTestService(t)
	sub, err := svc.Create("停用订阅", []string{"hash-1"}, nil, false)
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := d.Exec(`UPDATE subscriptions SET enabled=0 WHERE id=?`, sub.ID); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	if _, err := svc.PlainLinks(sub.Token, "203.0.113.9", "Shadowrocket/2.2.4"); err == nil {
		t.Fatal("a disabled subscription must not serve a body")
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM subscription_logs`).Scan(&n); err != nil {
		t.Fatalf("count logs: %v", err)
	}
	if n != 0 {
		t.Errorf("a rejected fetch should not be logged as an access, got %d rows", n)
	}
}
