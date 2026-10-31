package node

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const MaxBulkNodes = 500

var ErrInvalidNodeIDs = errors.New("node_ids must contain 1 to 500 unique positive real IDs")

// BulkToggleContext is an explicit state assignment, not an inversion. Every
// ID is checked in the same transaction before any row can be changed. It does
// not delete nodes or rewrite subscription selections.
func (s *Service) BulkToggleContext(ctx context.Context, ids []int64, enabled bool) (int, error) {
	if len(ids) == 0 || len(ids) > MaxBulkNodes {
		return 0, ErrInvalidNodeIDs
	}
	seen := make(map[int64]bool, len(ids))
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return 0, ErrInvalidNodeIDs
		}
		seen[id] = true
		args = append(args, id)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM nodes WHERE id IN (`+placeholders+`)`, args...)
	if err != nil {
		return 0, err
	}
	found := 0
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		found++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	if found != len(ids) {
		return 0, sql.ErrNoRows
	}
	updateArgs := []any{boolInt(enabled), time.Now().UTC().Format(time.RFC3339)}
	updateArgs = append(updateArgs, args...)
	res, err := tx.ExecContext(ctx, `UPDATE nodes SET enabled=?,updated_at=? WHERE id IN (`+placeholders+`)`, updateArgs...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n != int64(len(ids)) {
		return 0, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

func (s *Service) BulkToggle(ids []int64, enabled bool) (int, error) {
	return s.BulkToggleContext(context.Background(), ids, enabled)
}

func (s *Service) ToggleContext(ctx context.Context, id int64, enabled bool) error {
	_, err := s.BulkToggleContext(ctx, []int64{id}, enabled)
	return err
}
