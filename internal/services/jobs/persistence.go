package jobs

import (
	"context"
	"encoding/json"
	"time"
)

func (s *Service) ensureSchema(ctx context.Context) error {
	for _, query := range []string{
		`CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY,type TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,finished_at TEXT,payload TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC,id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status,created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS job_success (type TEXT PRIMARY KEY,finished_at TEXT NOT NULL,payload TEXT NOT NULL)`,
	} {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			return ErrStateStorage
		}
	}
	return nil
}

func (s *Service) persistLocked(task Task) error {
	updateDerived(&task)
	payload, err := json.Marshal(task)
	if err != nil {
		return ErrStateStorage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStateStorage
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,type,status,created_at,finished_at,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,finished_at=excluded.finished_at,payload=excluded.payload`, task.ID, task.Type, task.Status, task.CreatedAt, task.FinishedAt, string(payload)); err != nil {
		return ErrStateStorage
	}
	if (task.Status == Completed || task.Status == Partial) && task.Succeeded > 0 && task.FinishedAt != nil {
		success := Success{TaskID: task.ID, FinishedAt: *task.FinishedAt, Status: task.Status, Succeeded: task.Succeeded, Total: task.Total}
		blob, err := json.Marshal(success)
		if err != nil {
			return ErrStateStorage
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_success(type,finished_at,payload) VALUES(?,?,?) ON CONFLICT(type) DO UPDATE SET finished_at=excluded.finished_at,payload=excluded.payload WHERE excluded.finished_at>=job_success.finished_at`, task.Type, *task.FinishedAt, string(blob)); err != nil {
			return ErrStateStorage
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrStateStorage
	}
	return nil
}

// A restart cannot resume credential-bearing work safely. Old active records
// become cancelled with an explicit reason, and no upstream action is replayed.
func (s *Service) recoverInterrupted(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM jobs WHERE status IN ('queued','running','cancelling')`)
	if err != nil {
		return ErrStateStorage
	}
	var tasks []Task
	for rows.Next() {
		var payload []byte
		var task Task
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return ErrStateStorage
		}
		if err := json.Unmarshal(payload, &task); err != nil {
			rows.Close()
			return ErrStateStorage
		}
		tasks = append(tasks, task)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrStateStorage
	}
	for _, task := range tasks {
		finish := timestamp()
		task.Status, task.FinishedAt, task.Cancellable = Cancelled, &finish, false
		task.Message, task.Error = "task interrupted by server restart; not replayed", "interrupted_by_restart"
		if err := s.persistLocked(task); err != nil {
			return err
		}
	}
	return s.pruneLocked()
}

func (s *Service) pruneLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM jobs WHERE status NOT IN ('queued','running','cancelling') AND id NOT IN (SELECT id FROM jobs WHERE status NOT IN ('queued','running','cancelling') ORDER BY created_at DESC,id DESC LIMIT ?)`, s.options.HistoryLimit); err != nil {
		return ErrStateStorage
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM jobs`)
	if err != nil {
		return ErrStateStorage
	}
	defer rows.Close()
	retained := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return ErrStateStorage
		}
		retained[id] = true
	}
	if err := rows.Err(); err != nil {
		return ErrStateStorage
	}
	for id, e := range s.entries {
		if !isActive(e.task.Status) && !retained[id] {
			delete(s.entries, id)
		}
	}
	return nil
}
