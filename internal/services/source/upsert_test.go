package source

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Spittingjiu/subgo/internal/db"
	"github.com/Spittingjiu/subgo/internal/subconv"
)

const linkA = "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?flow=xtls-rprx-vision&fp=chrome&security=reality&pbk=AAA&sid=bb&type=tcp#test-node"
const linkARegen = "vless://22222222-2222-2222-2222-222222222222@1.2.3.4:443?flow=xtls-rprx-vision&fp=chrome&security=reality&pbk=ZZZ&sid=cc&type=tcp#test-node"

func newTestSvc(t *testing.T) (*Service, *db.DB, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	res, err := d.Exec(`INSERT INTO sources(name,source_type,panel_url,enabled,last_sync_status,created_at,updated_at) VALUES('t','sui_api','http://example.invalid',1,'pending',?,?)`, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("insert source: %v", err)
	}
	sid, _ := res.LastInsertId()
	return New(d.DB), d, sid
}

func addSub(t *testing.T, d *db.DB, hashes ...string) int64 {
	t.Helper()
	blob := "["
	for i, h := range hashes {
		if i > 0 {
			blob += ","
		}
		blob += `"` + h + `"`
	}
	blob += "]"
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.Exec(`INSERT INTO subscriptions(name,token,source_ids_json,node_ids_json,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)`, "s", "tok-"+now, "[]", blob, now, now)
	if err != nil {
		t.Fatalf("insert sub: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func subHashes(t *testing.T, d *db.DB, id int64) []string {
	t.Helper()
	var blob string
	if err := d.QueryRow(`SELECT node_ids_json FROM subscriptions WHERE id=?`, id).Scan(&blob); err != nil {
		t.Fatalf("read sub: %v", err)
	}
	var out []string
	if err := json.Unmarshal([]byte(blob), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func nodeRow(t *testing.T, d *db.DB, sourceID int64) (id int64, hash, identity, missing string, count int) {
	t.Helper()
	if err := d.QueryRow(`SELECT COUNT(*) FROM nodes WHERE source_id=?`, sourceID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count == 0 {
		return 0, "", "", "", 0
	}
	if err := d.QueryRow(`SELECT id,node_hash,identity,COALESCE(missing_since,'') FROM nodes WHERE source_id=?`, sourceID).Scan(&id, &hash, &identity, &missing); err != nil {
		t.Fatalf("read node: %v", err)
	}
	return
}

func TestEmptyFetchNeverWipesNodes(t *testing.T) {
	svc, d, sid := newTestSvc(t)
	if err := svc.upsertNodes(sid, []string{linkA}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	id0, hash0, _, _, _ := nodeRow(t, d, sid)

	sub := addSub(t, d, hash0)

	err := svc.upsertNodes(sid, []string{})
	if !errors.Is(err, errEmptyFetch) {
		t.Fatalf("want errEmptyFetch, got %v", err)
	}
	id1, hash1, _, _, count := nodeRow(t, d, sid)
	if count != 1 || id1 != id0 || hash1 != hash0 {
		t.Fatalf("node was altered on empty fetch: count=%d id=%d/%d hash=%s/%s", count, id1, id0, hash1, hash0)
	}
	if got := subHashes(t, d, sub); len(got) != 1 || got[0] != hash0 {
		t.Fatalf("subscription lost the node on empty fetch: %v", got)
	}
}

func TestRegeneratedLinkKeepsRowAndSubscription(t *testing.T) {
	svc, d, sid := newTestSvc(t)
	if err := svc.upsertNodes(sid, []string{linkA}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	id0, hash0, _, _, _ := nodeRow(t, d, sid)
	sub := addSub(t, d, hash0)

	if err := svc.upsertNodes(sid, []string{linkARegen}); err != nil {
		t.Fatalf("regen upsert: %v", err)
	}
	id1, hash1, _, _, count := nodeRow(t, d, sid)
	newHash := subconv.StableHash(linkARegen)
	if count != 1 {
		t.Fatalf("want 1 node, got %d", count)
	}
	if id1 != id0 {
		t.Fatalf("node row changed: %d -> %d", id0, id1)
	}
	if hash1 != newHash || hash1 == hash0 {
		t.Fatalf("hash not refreshed: %s (want %s)", hash1, newHash)
	}
	if got := subHashes(t, d, sub); len(got) != 1 || got[0] != newHash {
		t.Fatalf("subscription not re-linked: %v (want %s)", got, newHash)
	}
}

func TestMissingNodeGetsGracePeriod(t *testing.T) {
	svc, d, sid := newTestSvc(t)
	if err := svc.upsertNodes(sid, []string{linkA}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	_, hash0, _, _, _ := nodeRow(t, d, sid)
	sub := addSub(t, d, hash0)

	// Upstream still answers, but without our node (e.g. inbound disabled).
	other := "vless://33333333-3333-3333-3333-333333333333@5.6.7.8:8443?type=tcp&security=reality&sni=a.com&pbk=K&sid=11#other"
	if err := svc.upsertNodes(sid, []string{other}); err != nil {
		t.Fatalf("upsert without node: %v", err)
	}
	_, _, _, missing, count := nodeRow(t, d, sid)
	if count != 2 {
		t.Fatalf("grace period failed, want 2 nodes (kept one), got %d", count)
	}
	if missing == "" {
		t.Fatalf("missing_since not stamped")
	}
	var keptHash string
	if err := d.QueryRow(`SELECT node_hash FROM nodes WHERE source_id=? AND node_hash=?`, sid, hash0).Scan(&keptHash); err != nil {
		t.Fatalf("grace-kept node disappeared: %v", err)
	}
	if got := subHashes(t, d, sub); len(got) != 1 || got[0] != hash0 {
		t.Fatalf("subscription dropped node during grace: %v", got)
	}
}

func TestMissingNodeRemovedAfterGrace(t *testing.T) {
	svc, d, sid := newTestSvc(t)
	if err := svc.upsertNodes(sid, []string{linkA}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	_, hash0, _, _, _ := nodeRow(t, d, sid)
	old := time.Now().Add(-2 * nodeMissingGrace).UTC().Format(time.RFC3339)
	if err := svc.upsertNodes(sid, []string{linkA}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Simulate: node vanished long ago in an earlier sync.
	if _, err := d.Exec(`UPDATE nodes SET missing_since=? WHERE node_hash=?`, old, hash0); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	other := "vless://44444444-4444-4444-4444-444444444444@9.9.9.9:8443?type=tcp&security=reality&sni=a.com&pbk=K&sid=11#other2"
	if err := svc.upsertNodes(sid, []string{other}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	_, _, _, _, count := nodeRow(t, d, sid)
	if count != 1 {
		t.Fatalf("stale node not removed after grace, count=%d", count)
	}
}

// A panel that moves to another domain changes protocol|host|port identity, so
// the node looks brand new. Subscriptions must follow it instead of dropping it.
func TestHostRenameReLinksSubscriptions(t *testing.T) {
	svc, d, sid := newTestSvc(t)
	if err := svc.upsertNodes(sid, []string{linkA}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	_, hash0, _, _, _ := nodeRow(t, d, sid)
	sub := addSub(t, d, hash0)

	// Same node, new host.
	moved := "vless://11111111-1111-1111-1111-111111111111@9.9.9.9:443?flow=xtls-rprx-vision&fp=chrome&security=reality&pbk=AAA&sid=bb&type=tcp#test-node"
	if err := svc.upsertNodes(sid, []string{moved}); err != nil {
		t.Fatalf("moved upsert: %v", err)
	}
	newHash := subconv.StableHash(moved)
	got := subHashes(t, d, sub)
	if len(got) != 1 || got[0] != newHash {
		t.Fatalf("subscription did not follow the node to its new host: %v (want %s)", got, newHash)
	}
	// The old row stays for the grace window but must be hidden from output.
	var missing string
	if err := d.QueryRow(`SELECT COALESCE(missing_since,'') FROM nodes WHERE node_hash=?`, hash0).Scan(&missing); err != nil {
		t.Fatalf("old row gone: %v", err)
	}
	if missing == "" {
		t.Fatalf("old row should be in grace, not active")
	}
}
