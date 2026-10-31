package connectivity

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	failTTL    = 15 * time.Minute
	okTTL      = 30 * time.Minute
	unknownTTL = 5 * time.Minute
)

// EnsureSchema preserves the old no-return API. New context-aware callers must
// use EnsureSchemaContext so migration failures are visible.
func (s *Service) EnsureSchema() { _ = s.EnsureSchemaContext(context.Background()) }

// EnsureSchemaContext owns only connectivity metadata and invalidation triggers.
// The node generation prevents ABA races (changed link/eligibility, then changed
// back) without changing source synchronization or subscription selection logic.
func (s *Service) EnsureSchemaContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.schemaGate <- struct{}{}:
		defer func() { <-s.schemaGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.schemaReady {
		return nil
	}
	if s.db == nil {
		return ErrStorage
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return storageError(ctx, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS node_connectivity (
		node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
		status TEXT NOT NULL, latency_ms INTEGER, last_error TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL,
		code TEXT NOT NULL DEFAULT '', failure_class TEXT NOT NULL DEFAULT '', elapsed_ms INTEGER NOT NULL DEFAULT 0,
		node_hash TEXT NOT NULL DEFAULT '', link_version TEXT NOT NULL DEFAULT '',
		failure_count INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL DEFAULT '')`); err != nil {
		return storageError(ctx, err)
	}
	if err := addConnectivityColumns(ctx, tx, "nodes", []columnMigration{
		{"connectivity_generation", `ALTER TABLE nodes ADD COLUMN connectivity_generation INTEGER NOT NULL DEFAULT 1`},
	}); err != nil {
		return storageError(ctx, err)
	}
	if err := addConnectivityColumns(ctx, tx, "node_connectivity", []columnMigration{
		{"code", `ALTER TABLE node_connectivity ADD COLUMN code TEXT NOT NULL DEFAULT ''`},
		{"failure_class", `ALTER TABLE node_connectivity ADD COLUMN failure_class TEXT NOT NULL DEFAULT ''`},
		{"elapsed_ms", `ALTER TABLE node_connectivity ADD COLUMN elapsed_ms INTEGER NOT NULL DEFAULT 0`},
		{"node_hash", `ALTER TABLE node_connectivity ADD COLUMN node_hash TEXT NOT NULL DEFAULT ''`},
		{"link_version", `ALTER TABLE node_connectivity ADD COLUMN link_version TEXT NOT NULL DEFAULT ''`},
		{"failure_count", `ALTER TABLE node_connectivity ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0`},
		{"expires_at", `ALTER TABLE node_connectivity ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''`},
	}); err != nil {
		return storageError(ctx, err)
	}
	stmts := []string{
		`CREATE TRIGGER IF NOT EXISTS subgo_connectivity_node_changed_v1
		 AFTER UPDATE OF raw_link,node_hash,enabled,missing_since,source_id ON nodes
		 WHEN OLD.raw_link IS NOT NEW.raw_link OR OLD.node_hash IS NOT NEW.node_hash
		   OR OLD.enabled IS NOT NEW.enabled OR OLD.missing_since IS NOT NEW.missing_since
		   OR OLD.source_id IS NOT NEW.source_id
		 BEGIN
		   UPDATE nodes SET connectivity_generation=connectivity_generation+1 WHERE id=NEW.id;
		   DELETE FROM node_connectivity WHERE node_id=NEW.id;
		 END`,
		`CREATE TRIGGER IF NOT EXISTS subgo_connectivity_source_enabled_v1
		 AFTER UPDATE OF enabled ON sources WHEN OLD.enabled IS NOT NEW.enabled
		 BEGIN
		   UPDATE nodes SET connectivity_generation=connectivity_generation+1 WHERE source_id=NEW.id;
		   DELETE FROM node_connectivity WHERE node_id IN (SELECT id FROM nodes WHERE source_id=NEW.id);
		 END`,
		`CREATE TRIGGER IF NOT EXISTS subgo_connectivity_node_deleted_v1
		 AFTER DELETE ON nodes BEGIN DELETE FROM node_connectivity WHERE node_id=OLD.id; END`,
		`CREATE INDEX IF NOT EXISTS idx_node_connectivity_expires ON node_connectivity(expires_at)`,
		// Legacy observations have neither link provenance nor strict TLS/204
		// semantics. Invalidate all of them, especially versionless failures.
		`DELETE FROM node_connectivity WHERE node_hash='' OR link_version='' OR expires_at=''`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return storageError(ctx, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return storageError(ctx, err)
	}
	s.schemaReady = true
	return nil
}

type columnMigration struct{ name, statement string }

func addConnectivityColumns(ctx context.Context, tx *sql.Tx, table string, migrations []columnMigration) error {
	// table and statements are hard-coded by this package, never caller input.
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, migration := range migrations {
		if !columns[migration.name] {
			if _, err := tx.ExecContext(ctx, migration.statement); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExpireContext must run before legacy public subscription SQL when auto-prune
// is enabled. Expired/invalid rows are removed, so a bare status='fail' predicate
// cannot keep pruning indefinitely. No subscription selection is modified here.
func (s *Service) ExpireContext(ctx context.Context) error {
	if err := s.EnsureSchemaContext(ctx); err != nil {
		return err
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `DELETE FROM node_connectivity
		WHERE node_hash='' OR link_version=''
		 OR status NOT IN ('ok','fail','unknown')
		 OR (status='fail' AND (failure_class!='remote' OR failure_count<2 OR code NOT IN ('remote_error','remote_timeout')))
		 OR julianday(checked_at) IS NULL OR julianday(checked_at)>julianday(?)
		 OR julianday(expires_at) IS NULL OR julianday(expires_at)<=julianday(?)
		 OR julianday(checked_at)<=julianday(?) -
		   CASE status WHEN 'fail' THEN 15.0/1440 WHEN 'ok' THEN 30.0/1440 ELSE 5.0/1440 END
		 OR NOT EXISTS (SELECT 1 FROM nodes n JOIN sources s ON s.id=n.source_id
		   WHERE n.id=node_connectivity.node_id AND n.node_hash=node_connectivity.node_hash
		     AND CAST(n.connectivity_generation AS TEXT)=node_connectivity.link_version
		     AND n.enabled=1 AND s.enabled=1 AND COALESCE(n.missing_since,'')='')`, now, now, now)
	if err != nil {
		return storageError(ctx, err)
	}
	return nil
}

func (s *Service) List() ([]Result, error) { return s.ListContext(context.Background()) }

// ListContext returns effective stored state: the first fresh remote failure is
// unknown; only the second consecutive failure is fail. Check results/callbacks
// represent individual observations, so their first genuine failure is fail.
func (s *Service) ListContext(ctx context.Context) ([]Result, error) {
	if err := s.ExpireContext(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,status,latency_ms,last_error,checked_at,
		code,failure_class,elapsed_ms,node_hash,link_version FROM node_connectivity ORDER BY checked_at DESC,node_id DESC`)
	if err != nil {
		return nil, storageError(ctx, err)
	}
	defer rows.Close()
	out := make([]Result, 0)
	for rows.Next() {
		var r Result
		var lat sql.NullInt64
		if err := rows.Scan(&r.NodeID, &r.Status, &lat, &r.LastError, &r.CheckedAt,
			&r.Code, &r.FailureClass, &r.ElapsedMS, &r.NodeHash, &r.LinkVersion); err != nil {
			return nil, storageError(ctx, err)
		}
		// Never trust old/hand-edited last_error or classification strings.
		info, valid := resultCodes[r.Code]
		if !valid {
			r.Code, info = CodeExecutorError, resultCodes[CodeExecutorError]
			r.Status = StatusUnknown
		}
		r.LastError, r.FailureClass = info.message, info.class
		if r.ElapsedMS < 0 {
			r.ElapsedMS = 0
		}
		if lat.Valid && lat.Int64 >= 0 && r.Status == StatusOK {
			r.LatencyMS = &lat.Int64
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, storageError(ctx, err)
	}
	return out, nil
}

func (s *Service) targetCurrent(ctx context.Context, t Target) (bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT n.id FROM nodes n JOIN sources s ON s.id=n.source_id
		WHERE n.id=? AND n.source_id=? AND n.raw_link=? AND n.node_hash=?
		 AND CAST(n.connectivity_generation AS TEXT)=? AND n.enabled=1 AND s.enabled=1
		 AND COALESCE(n.missing_since,'')=''`, t.ID, t.SourceID, t.RawLink, t.NodeHash, t.LinkVersion).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, storageError(ctx, err)
	}
	return true, nil
}

// saveContext validates raw/hash/generation/eligibility again in the write
// transaction and in the INSERT SELECT itself. Late results cannot replace a
// newer link's observation. False means stale, not a storage error.
func (s *Service) saveContext(ctx context.Context, t Target, r Result, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, storageError(ctx, err)
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT n.id FROM nodes n JOIN sources s ON s.id=n.source_id
		WHERE n.id=? AND n.source_id=? AND n.raw_link=? AND n.node_hash=?
		 AND CAST(n.connectivity_generation AS TEXT)=? AND n.enabled=1 AND s.enabled=1
		 AND COALESCE(n.missing_since,'')=''`, t.ID, t.SourceID, t.RawLink, t.NodeHash, t.LinkVersion).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, storageError(ctx, err)
	}
	status := r.Status
	failures := 0
	if r.Status == StatusFail && r.FailureClass == FailureRemote {
		failures = 1
		var previousStatus, previousCode, class, hash, version, checkedAt, expiresAt string
		var count int
		err := tx.QueryRowContext(ctx, `SELECT status,code,failure_class,node_hash,link_version,failure_count,checked_at,expires_at
			FROM node_connectivity WHERE node_id=?`, t.ID).Scan(&previousStatus, &previousCode, &class, &hash, &version, &count, &checkedAt, &expiresAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, storageError(ctx, err)
		}
		checked, checkedErr := time.Parse(time.RFC3339Nano, checkedAt)
		expires, expiresErr := time.Parse(time.RFC3339Nano, expiresAt)
		if err == nil && class == FailureRemote && (previousCode == CodeRemoteError || previousCode == CodeRemoteTimeout) &&
			hash == t.NodeHash && version == t.LinkVersion && count > 0 &&
			(previousStatus == StatusUnknown || previousStatus == StatusFail) && checkedErr == nil && expiresErr == nil &&
			!checked.After(now) && expires.After(now) && now.Sub(checked) < resultTTL(previousStatus) {
			failures = 2 // confirmation threshold; no unbounded counter
		}
		status = StatusUnknown
		if failures >= 2 {
			status = StatusFail
		}
	}
	expiresAt := now.Add(resultTTL(status)).UTC().Format(time.RFC3339Nano)
	var latency any
	if r.LatencyMS != nil && status == StatusOK {
		latency = *r.LatencyMS
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO node_connectivity
		(node_id,status,latency_ms,last_error,checked_at,code,failure_class,elapsed_ms,node_hash,link_version,failure_count,expires_at)
		SELECT n.id,?,?,?,?,?,?,?,?,?,?,? FROM nodes n JOIN sources s ON s.id=n.source_id
		WHERE n.id=? AND n.source_id=? AND n.raw_link=? AND n.node_hash=?
		 AND CAST(n.connectivity_generation AS TEXT)=? AND n.enabled=1 AND s.enabled=1
		 AND COALESCE(n.missing_since,'')=''
		ON CONFLICT(node_id) DO UPDATE SET status=excluded.status,latency_ms=excluded.latency_ms,
		 last_error=excluded.last_error,checked_at=excluded.checked_at,code=excluded.code,
		 failure_class=excluded.failure_class,elapsed_ms=excluded.elapsed_ms,node_hash=excluded.node_hash,
		 link_version=excluded.link_version,failure_count=excluded.failure_count,expires_at=excluded.expires_at`,
		status, latency, r.LastError, r.CheckedAt, r.Code, r.FailureClass, r.ElapsedMS, t.NodeHash, t.LinkVersion, failures, expiresAt,
		t.ID, t.SourceID, t.RawLink, t.NodeHash, t.LinkVersion)
	if err != nil {
		return false, storageError(ctx, err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return false, storageError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return false, storageError(ctx, err)
	}
	return count == 1, nil
}

func resultTTL(status string) time.Duration {
	switch status {
	case StatusFail:
		return failTTL
	case StatusOK:
		return okTTL
	default:
		return unknownTTL
	}
}
