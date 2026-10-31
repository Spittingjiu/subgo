package source

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrSyncInProgress = errors.New("source sync already running")
	ErrSourceDisabled = errors.New("source is disabled")
	ErrInvalidScope   = errors.New("invalid source scope")
	// Export the existing marker without changing the empty-snapshot algorithm.
	ErrEmptyFetch = errEmptyFetch
)

const MaxSyncSources = 500

// beginSync is shared by every caller, including the legacy synchronous API.
// Unrelated sources may proceed in parallel; the same source cannot re-enter.
func (s *Service) beginSync(id int64) bool {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if s.syncing == nil {
		s.syncing = make(map[int64]bool)
	}
	if s.syncing[id] {
		return false
	}
	s.syncing[id] = true
	return true
}

func (s *Service) endSync(id int64) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	delete(s.syncing, id)
}

// ResolveSyncScope freezes a task's eligible sources at submission time.
// nil means all enabled non-local sources. A non-nil empty slice means none.
// Explicit unknown/duplicate/non-positive IDs are rejected, never broadened.
func (s *Service) ResolveSyncScope(ctx context.Context, ids []int64) ([]int64, error) {
	out := make([]int64, 0)
	if ids != nil && len(ids) == 0 {
		return out, nil
	}
	if len(ids) > MaxSyncSources {
		return nil, ErrInvalidScope
	}
	q := `SELECT id,source_type,enabled FROM sources`
	args := make([]any, 0, len(ids))
	if ids != nil {
		seen := make(map[int64]bool, len(ids))
		for _, id := range ids {
			if id <= 0 || seen[id] {
				return nil, ErrInvalidScope
			}
			seen[id] = true
			args = append(args, id)
		}
		q += ` WHERE id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + `)`
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		var id int64
		var typ string
		var enabled int
		if err := rows.Scan(&id, &typ, &enabled); err != nil {
			return nil, err
		}
		found++
		if typ != "local" && enabled == 1 {
			out = append(out, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if ids != nil && found != len(ids) || len(out) > MaxSyncSources {
		return nil, ErrInvalidScope
	}
	return out, nil
}
