// Package jobs provides bounded, observable background work for management APIs.
// It stores only safe IDs/counters/reasons, never links or upstream credentials.
package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Spittingjiu/subgo/internal/services/connectivity"
)

const (
	TypeSync            = "sync"
	TypeConnectivity    = "connectivity"
	Queued              = "queued"
	Running             = "running"
	Completed           = "completed"
	Partial             = "partial"
	Failed              = "failed"
	Cancelling          = "cancelling"
	Cancelled           = "cancelled"
	DefaultHistoryLimit = 50
	DefaultQueueLimit   = 32
	MaxResults          = 200
)

var (
	ErrNotFound     = errors.New("task not found")
	ErrClosed       = errors.New("task service is closed")
	ErrQueueFull    = errors.New("task queue is full")
	ErrStateStorage = errors.New("task state storage failed")
)

// ConflictError points to the already accepted job rather than re-entering it.
type ConflictError struct{ TaskID string }

func (e *ConflictError) Error() string { return "overlapping task already queued or running" }

type SourceExecutor interface {
	ResolveSyncScope(context.Context, []int64) ([]int64, error)
	SyncContext(context.Context, int64) error
}

type ConnectivityExecutor interface {
	SelectTargets(context.Context, connectivity.Scope) ([]connectivity.Target, error)
	CheckTargetsContext(context.Context, []connectivity.Target, func(connectivity.Result)) ([]connectivity.Result, error)
}

// Result is deliberately a small allowlist; raw error strings are not persisted.
type Result struct {
	SourceID  int64  `json:"source_id,omitempty"`
	NodeID    int64  `json:"node_id,omitempty"`
	Status    string `json:"status"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Error     string `json:"error"`
	LatencyMS *int64 `json:"latency_ms,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

type Scope struct {
	SourceIDs []int64 `json:"source_ids,omitempty"`
	NodeIDs   []int64 `json:"node_ids,omitempty"`
	SourceID  int64   `json:"source_id,omitempty"`
	All       bool    `json:"all"`
}

type Task struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	Status           string   `json:"status"`
	Total            int      `json:"total"`
	Completed        int      `json:"completed"`
	Succeeded        int      `json:"succeeded"`
	Failed           int      `json:"failed"`
	Skipped          int      `json:"skipped"`
	ProgressPercent  int      `json:"progress_percent"`
	ElapsedMS        int64    `json:"elapsed_ms"`
	CreatedAt        string   `json:"created_at"`
	StartedAt        *string  `json:"started_at,omitempty"`
	FinishedAt       *string  `json:"finished_at,omitempty"`
	Message          string   `json:"message"`
	Error            string   `json:"error"`
	Results          []Result `json:"results"`
	ResultsTruncated int      `json:"results_truncated"`
	Cancellable      bool     `json:"cancellable"`
	Trigger          string   `json:"trigger"`
	Scope            Scope    `json:"scope"`
}

type Success struct {
	TaskID     string `json:"task_id"`
	FinishedAt string `json:"finished_at"`
	Status     string `json:"status"`
	Succeeded  int    `json:"succeeded"`
	Total      int    `json:"total"`
}

type Snapshot struct {
	Tasks         []Task             `json:"tasks"`
	Active        []Task             `json:"active"`
	Recent        []Task             `json:"recent"`
	RecentSuccess map[string]Success `json:"recent_success"`
	HistoryLimit  int                `json:"history_limit"`
}

type Options struct {
	HistoryLimit int
	QueueLimit   int
	TaskTimeout  time.Duration
}

type entry struct {
	task       Task
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	doneClosed bool
	keys       []string
	sourceIDs  []int64
	targets    []connectivity.Target
}

type Service struct {
	db           *sql.DB
	sources      SourceExecutor
	connectivity ConnectivityExecutor
	options      Options
	root         context.Context
	stop         context.CancelFunc
	mu           sync.Mutex
	entries      map[string]*entry
	reservations map[string]string
	queues       map[string]chan *entry
	wg           sync.WaitGroup
	closed       bool
	closeDone    chan struct{}
}

func New(db *sql.DB, sources SourceExecutor, conn ConnectivityExecutor) (*Service, error) {
	return NewWithOptions(db, sources, conn, Options{})
}

func NewWithOptions(db *sql.DB, sources SourceExecutor, conn ConnectivityExecutor, options Options) (*Service, error) {
	if db == nil || sources == nil || conn == nil {
		return nil, errors.New("task executors required")
	}
	if options.HistoryLimit <= 0 || options.HistoryLimit > 100 {
		options.HistoryLimit = DefaultHistoryLimit
	}
	if options.QueueLimit <= 0 || options.QueueLimit > 64 {
		options.QueueLimit = DefaultQueueLimit
	}
	if options.TaskTimeout <= 0 {
		options.TaskTimeout = 20 * time.Minute
	}
	root, stop := context.WithCancel(context.Background())
	s := &Service{db: db, sources: sources, connectivity: conn, options: options, root: root, stop: stop,
		entries: map[string]*entry{}, reservations: map[string]string{},
		queues: map[string]chan *entry{TypeSync: make(chan *entry, options.QueueLimit), TypeConnectivity: make(chan *entry, options.QueueLimit)}, closeDone: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.ensureSchema(ctx); err != nil {
		stop()
		return nil, err
	}
	if err := s.recoverInterrupted(ctx); err != nil {
		stop()
		return nil, err
	}
	for _, kind := range []string{TypeSync, TypeConnectivity} {
		s.wg.Add(1)
		go s.worker(kind)
	}
	return s, nil
}

func timestamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00") }
func isActive(status string) bool {
	return status == Queued || status == Running || status == Cancelling
}

func (s *Service) SubmitSync(ctx context.Context, ids []int64, trigger string) (Task, error) {
	resolved, err := s.sources.ResolveSyncScope(ctx, ids)
	if err != nil {
		return Task{}, err
	}
	keys := make([]string, 0, len(resolved))
	for _, id := range resolved {
		keys = append(keys, fmt.Sprintf("source:%d", id))
	}
	return s.submit(TypeSync, trigger, Scope{SourceIDs: cloneIDs(resolved), All: ids == nil}, keys, resolved, nil)
}

func (s *Service) SubmitConnectivity(ctx context.Context, scope connectivity.Scope, trigger string) (Task, error) {
	targets, err := s.connectivity.SelectTargets(ctx, scope)
	if err != nil {
		return Task{}, err
	}
	ids := make([]int64, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.ID)
	}
	keys := []string{}
	// A single bounded kernel lane also protects legacy checks from overlap.
	if len(targets) > 0 {
		keys = append(keys, TypeConnectivity)
	}
	return s.submit(TypeConnectivity, trigger, Scope{NodeIDs: ids, SourceID: scope.SourceID, All: scope.NodeIDs == nil && scope.SourceID == 0}, keys, nil, targets)
}

func cloneIDs(ids []int64) []int64 { return append([]int64{}, ids...) }
func safeTrigger(trigger string) string {
	switch trigger {
	case "scheduler", "bridge", "upstream_change", "legacy":
		return trigger
	default:
		return "manual"
	}
}

func (s *Service) submit(kind, trigger string, scope Scope, keys []string, ids []int64, targets []connectivity.Target) (Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Task{}, ErrClosed
	}
	for _, key := range keys {
		if id := s.reservations[key]; id != "" {
			return Task{}, &ConflictError{TaskID: id}
		}
	}
	active := 0
	for _, e := range s.entries {
		if isActive(e.task.Status) {
			active++
		}
	}
	if active >= s.options.QueueLimit {
		return Task{}, ErrQueueFull
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return Task{}, errors.New("task ID generation failed")
	}
	ctx, cancel := context.WithCancel(s.root)
	e := &entry{ctx: ctx, cancel: cancel, done: make(chan struct{}), keys: keys, sourceIDs: cloneIDs(ids), targets: append([]connectivity.Target(nil), targets...)}
	e.task = Task{ID: hex.EncodeToString(b), Type: kind, Status: Queued, Total: len(ids) + len(targets), CreatedAt: timestamp(),
		Message: "task queued", Results: []Result{}, Cancellable: true, Trigger: safeTrigger(trigger), Scope: scope}
	if e.task.Total == 0 {
		finish := timestamp()
		e.task.Status, e.task.Message, e.task.FinishedAt, e.task.Cancellable, e.task.ProgressPercent = Completed, "no eligible items in the explicit scope", &finish, false, 100
	}
	if err := s.persistLocked(e.task); err != nil {
		cancel()
		return Task{}, ErrStateStorage
	}
	s.entries[e.task.ID] = e
	if e.task.Total == 0 {
		cancel()
		e.doneClosed = true
		close(e.done)
		_ = s.pruneLocked()
	} else {
		for _, key := range keys {
			s.reservations[key] = e.task.ID
		}
		s.queues[kind] <- e
	}
	return snapshot(e.task), nil
}

func (s *Service) worker(kind string) {
	defer s.wg.Done()
	for {
		select {
		case <-s.root.Done():
			return
		case e := <-s.queues[kind]:
			s.execute(e)
		}
	}
}

func (s *Service) execute(e *entry) {
	s.mu.Lock()
	if e.doneClosed {
		s.mu.Unlock()
		return
	}
	if e.ctx.Err() != nil || s.closed {
		s.finishLocked(e, context.Canceled)
		s.mu.Unlock()
		return
	}
	start := timestamp()
	e.task.StartedAt, e.task.Status, e.task.Message = &start, Running, "task running"
	if err := s.persistLocked(e.task); err != nil {
		s.finishLocked(e, ErrStateStorage)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, s.options.TaskTimeout)
	defer cancel()
	var workErr error
	// A panic must still release reservations and yield a terminal task.
	func() {
		defer func() {
			if recover() != nil {
				workErr = errors.New("task executor failed")
			}
		}()
		if e.task.Type == TypeSync {
			for _, id := range e.sourceIDs {
				if err := ctx.Err(); err != nil {
					workErr = err
					break
				}
				started := time.Now()
				err := s.sources.SyncContext(ctx, id)
				r := syncResult(id, err)
				r.ElapsedMS = time.Since(started).Milliseconds()
				if err := s.record(e, r); err != nil {
					workErr = err
					break
				}
				if err := ctx.Err(); err != nil {
					workErr = err
					break
				}
			}
		} else {
			_, workErr = s.connectivity.CheckTargetsContext(ctx, e.targets, func(r connectivity.Result) {
				if err := s.record(e, connectivityResult(r)); err != nil {
					e.cancel()
				}
			})
		}
	}()
	s.mu.Lock()
	s.finishLocked(e, workErr)
	s.mu.Unlock()
}

func (s *Service) record(e *entry, result Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.doneClosed {
		return context.Canceled
	}
	e.task.Completed++
	switch result.Status {
	case "ok":
		e.task.Succeeded++
	case "cancelled", "skipped":
		e.task.Skipped++
	default:
		e.task.Failed++
	}
	if len(e.task.Results) < MaxResults {
		e.task.Results = append(e.task.Results, result)
	} else {
		e.task.ResultsTruncated++
	}
	updateDerived(&e.task)
	if err := s.persistLocked(e.task); err != nil {
		e.task.Error = ErrStateStorage.Error()
		return ErrStateStorage
	}
	return nil
}

func (s *Service) finishLocked(e *entry, workErr error) {
	if e.doneClosed {
		return
	}
	finish := timestamp()
	e.task.FinishedAt, e.task.Cancellable = &finish, false
	if e.task.Error == ErrStateStorage.Error() || errors.Is(workErr, ErrStateStorage) {
		e.task.Status, e.task.Error, e.task.Message = Failed, ErrStateStorage.Error(), "task state could not be stored"
	} else if e.task.Status == Cancelling || errors.Is(workErr, context.Canceled) || e.ctx.Err() != nil {
		e.task.Status, e.task.Message = Cancelled, "task cancelled; completed results are retained"
	} else if workErr != nil || e.task.Failed > 0 || e.task.Skipped > 0 {
		e.task.Status = Failed
		if e.task.Succeeded > 0 {
			e.task.Status = Partial
		}
		e.task.Message = "task finished with unsuccessful or skipped items"
		if workErr != nil {
			if errors.Is(workErr, context.DeadlineExceeded) {
				e.task.Error = "task deadline exceeded"
			} else {
				e.task.Error = "task executor failed"
			}
		}
	} else {
		e.task.Status, e.task.Message = Completed, "task completed"
	}
	updateDerived(&e.task)
	if err := s.persistLocked(e.task); err != nil {
		e.task.Status, e.task.Error, e.task.Message = Failed, ErrStateStorage.Error(), "task state could not be stored"
	}
	for _, key := range e.keys {
		if s.reservations[key] == e.task.ID {
			delete(s.reservations, key)
		}
	}
	e.cancel()
	// Drop credential-bearing execution snapshots as soon as work is reaped.
	e.targets, e.sourceIDs = nil, nil
	e.doneClosed = true
	close(e.done)
	_ = s.pruneLocked()
}

func updateDerived(task *Task) {
	task.Cancellable = task.Status == Queued || task.Status == Running
	if task.Total > 0 {
		task.ProgressPercent = task.Completed * 100 / task.Total
	} else if !isActive(task.Status) {
		task.ProgressPercent = 100
	}
	if task.StartedAt != nil {
		start, err := time.Parse(time.RFC3339Nano, *task.StartedAt)
		if err == nil {
			end := time.Now()
			if task.FinishedAt != nil {
				if parsed, err := time.Parse(time.RFC3339Nano, *task.FinishedAt); err == nil {
					end = parsed
				}
			}
			task.ElapsedMS = end.Sub(start).Milliseconds()
			if task.ElapsedMS < 0 {
				task.ElapsedMS = 0
			}
		}
	}
}

func snapshot(task Task) Task {
	updateDerived(&task)
	task.Results = append([]Result{}, task.Results...)
	for i := range task.Results {
		if task.Results[i].LatencyMS != nil {
			value := *task.Results[i].LatencyMS
			task.Results[i].LatencyMS = &value
		}
	}
	if task.StartedAt != nil {
		value := *task.StartedAt
		task.StartedAt = &value
	}
	if task.FinishedAt != nil {
		value := *task.FinishedAt
		task.FinishedAt = &value
	}
	task.Scope.SourceIDs = cloneIDs(task.Scope.SourceIDs)
	task.Scope.NodeIDs = cloneIDs(task.Scope.NodeIDs)
	return task
}

func (s *Service) Get(ctx context.Context, id string) (Task, error) {
	s.mu.Lock()
	if e := s.entries[id]; e != nil {
		task := snapshot(e.task)
		s.mu.Unlock()
		return task, nil
	}
	s.mu.Unlock()
	var payload []byte
	if err := s.db.QueryRowContext(ctx, `SELECT payload FROM jobs WHERE id=?`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Task{}, ErrNotFound
		}
		return Task{}, ErrStateStorage
	}
	var task Task
	if err := json.Unmarshal(payload, &task); err != nil {
		return Task{}, ErrStateStorage
	}
	return snapshot(task), nil
}

func (s *Service) Wait(ctx context.Context, id string) (Task, error) {
	s.mu.Lock()
	e := s.entries[id]
	if e == nil {
		s.mu.Unlock()
		return s.Get(ctx, id)
	}
	done := e.done
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return Task{}, ctx.Err()
	case <-done:
		return s.Get(ctx, id)
	}
}

func (s *Service) Cancel(ctx context.Context, id string) (Task, error) {
	s.mu.Lock()
	e := s.entries[id]
	if e == nil {
		s.mu.Unlock()
		return s.Get(ctx, id)
	}
	if !isActive(e.task.Status) {
		task := snapshot(e.task)
		s.mu.Unlock()
		return task, nil
	}
	queued := e.task.Status == Queued
	e.task.Status, e.task.Message, e.task.Cancellable = Cancelling, "cancellation requested; waiting for cleanup", false
	e.cancel()
	if queued {
		s.finishLocked(e, context.Canceled)
	} else if err := s.persistLocked(e.task); err != nil {
		e.task.Error = ErrStateStorage.Error()
	}
	task := snapshot(e.task)
	s.mu.Unlock()
	return task, nil
}

func (s *Service) List(ctx context.Context) (Snapshot, error) {
	out := Snapshot{Tasks: []Task{}, Active: []Task{}, Recent: []Task{}, RecentSuccess: map[string]Success{}, HistoryLimit: s.options.HistoryLimit}
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM jobs ORDER BY created_at DESC,id DESC LIMIT ?`, s.options.HistoryLimit+s.options.QueueLimit)
	if err != nil {
		return out, ErrStateStorage
	}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			rows.Close()
			return out, ErrStateStorage
		}
		var task Task
		if err := json.Unmarshal(payload, &task); err != nil {
			rows.Close()
			return out, ErrStateStorage
		}
		s.mu.Lock()
		if e := s.entries[task.ID]; e != nil {
			task = e.task
		}
		task = snapshot(task)
		s.mu.Unlock()
		out.Tasks = append(out.Tasks, task)
		if isActive(task.Status) {
			out.Active = append(out.Active, task)
		} else if len(out.Recent) < s.options.HistoryLimit {
			out.Recent = append(out.Recent, task)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, ErrStateStorage
	}
	rows, err = s.db.QueryContext(ctx, `SELECT type,payload FROM job_success`)
	if err != nil {
		return out, ErrStateStorage
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var payload []byte
		var success Success
		if err := rows.Scan(&kind, &payload); err != nil {
			return out, ErrStateStorage
		}
		if err := json.Unmarshal(payload, &success); err != nil {
			return out, ErrStateStorage
		}
		out.RecentSuccess[kind] = success
	}
	if err := rows.Err(); err != nil {
		return out, ErrStateStorage
	}
	return out, nil
}

// Close cancels queued and running jobs and waits until executors have cleaned up.
func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return nil
	}
	s.closed = true
	s.stop()
	for _, e := range s.entries {
		if !isActive(e.task.Status) {
			continue
		}
		queued := e.task.Status == Queued
		e.task.Status, e.task.Message = Cancelling, "server shutting down"
		e.cancel()
		if queued {
			s.finishLocked(e, context.Canceled)
		} else {
			_ = s.persistLocked(e.task)
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
	close(s.closeDone)
	return nil
}
