package connectivity

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200

	StatusOK      = "ok"
	StatusFail    = "fail"
	StatusUnknown = "unknown"

	FailureRemote    = "remote"
	FailureConfig    = "config"
	FailureKernel    = "kernel"
	FailureTarget    = "target"
	FailureLocal     = "local"
	FailureCancelled = "cancelled"

	CodeOK               = "ok"
	CodeRemoteError      = "remote_error"
	CodeRemoteTimeout    = "remote_timeout"
	CodeUnsupportedLink  = "unsupported_link"
	CodeKernelMissing    = "kernel_missing"
	CodeConfigInvalid    = "config_invalid"
	CodeConfigTimeout    = "config_timeout"
	CodeConfigWrite      = "config_write_failed"
	CodeTempDir          = "temp_dir_failed"
	CodeTempCleanup      = "temp_cleanup_failed"
	CodePortUnavailable  = "local_port_unavailable"
	CodeKernelStart      = "kernel_start_failed"
	CodeKernelExited     = "kernel_exited"
	CodeKernelTimeout    = "kernel_timeout"
	CodeProxyNotReady    = "proxy_not_ready"
	CodeProxyUnavailable = "local_proxy_unavailable"
	CodeProxyAuth        = "local_proxy_auth_failed"
	CodeTargetInvalid    = "target_invalid"
	CodeTargetTLS        = "target_tls_failed"
	CodeTargetStatus     = "target_status_unexpected"
	CodeTargetChanged    = "target_changed"
	CodeCancelled        = "cancelled"
	CodeDeadline         = "deadline_exceeded"
	CodeExecutorError    = "executor_error"
)

var (
	ErrInvalidScope    = errors.New("invalid connectivity scope")
	ErrCheckInProgress = errors.New("connectivity check already in progress")
	ErrStorage         = errors.New("connectivity storage unavailable")
)

// Scope distinguishes an omitted node list (all eligible nodes, with a bounded
// limit) from an explicitly empty list (no nodes). NodeIDs and SourceID intersect.
// Zero Limit checks all explicit IDs, or defaults to 50 for a full/source scope.
// Negative limits, limits over 200, nonpositive node IDs and missing IDs are errors.
// Disabled/missing nodes and disabled sources are filtered, not expanded.
type Scope struct {
	NodeIDs  []int64 `json:"node_ids"`
	SourceID int64   `json:"source_id"`
	Limit    int     `json:"limit"`
}

// Target is an immutable detection-time snapshot. LinkVersion is the node's
// connectivity generation, not a credential. Only SelectTargets should create
// targets for checks: callers must not refresh a queued snapshot before saving it.
type Target struct {
	ID          int64  `json:"id"`
	SourceID    int64  `json:"source_id"`
	RawLink     string `json:"-"`
	NodeHash    string `json:"-"`
	LinkVersion string `json:"-"`
}

type Result struct {
	NodeID       int64  `json:"node_id"`
	Status       string `json:"status"`
	LatencyMS    *int64 `json:"latency_ms"`
	LastError    string `json:"last_error"`
	CheckedAt    string `json:"checked_at"`
	Code         string `json:"code"`
	FailureClass string `json:"failure_class"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	NodeHash     string `json:"-"`
	LinkVersion  string `json:"-"`
}

// Executor must honor ctx. Only a genuine remote transport failure should return
// StatusFail with FailureRemote. Config/kernel/target errors are unknown, never
// subscription-pruning evidence. Untrusted error strings are not published.
type Executor interface {
	Check(context.Context, Target) Result
}

type ExecutorFunc func(context.Context, Target) Result

func (f ExecutorFunc) Check(ctx context.Context, t Target) Result { return f(ctx, t) }

type Service struct {
	db          *sql.DB
	executor    Executor
	checking    atomic.Bool
	schemaGate  chan struct{}
	schemaReady bool // guarded by schemaGate
	now         func() time.Time
}

func New(db *sql.DB) *Service { return NewWithExecutor(db, nil) }

func NewWithExecutor(db *sql.DB, executor Executor) *Service {
	if executor == nil {
		executor = newMihomoExecutor()
	}
	return &Service{db: db, executor: executor, schemaGate: make(chan struct{}, 1), now: time.Now}
}

// SelectTargets validates existence before limiting: an invalid ID must not be
// hidden by a smaller limit or by an enabled/source filter. It does not acquire
// the check guard, so jobs can prepare a snapshot without starting an executor.
func (s *Service) SelectTargets(ctx context.Context, scope Scope) ([]Target, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if scope.SourceID < 0 || scope.Limit < 0 || scope.Limit > MaxLimit || len(scope.NodeIDs) > MaxLimit {
		return nil, ErrInvalidScope
	}
	explicit := scope.NodeIDs != nil
	ids := make([]int64, 0, len(scope.NodeIDs))
	seen := make(map[int64]bool, len(scope.NodeIDs))
	for _, id := range scope.NodeIDs {
		if id <= 0 {
			return nil, ErrInvalidScope
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if err := s.EnsureSchemaContext(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, storageError(ctx, err)
	}
	defer tx.Rollback()
	if scope.SourceID != 0 {
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM sources WHERE id=?`, scope.SourceID).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidScope
		}
		if err != nil {
			return nil, storageError(ctx, err)
		}
	}
	if len(ids) > 0 {
		args := idArgs(ids)
		var count int
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id IN (`+placeholders(len(ids))+`)`, args...).Scan(&count)
		if err != nil {
			return nil, storageError(ctx, err)
		}
		if count != len(ids) {
			return nil, ErrInvalidScope
		}
	}
	if explicit && len(ids) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, storageError(ctx, err)
		}
		return []Target{}, nil
	}
	q := `SELECT n.id,n.source_id,n.raw_link,n.node_hash,CAST(n.connectivity_generation AS TEXT)
		FROM nodes n JOIN sources s ON s.id=n.source_id
		WHERE n.enabled=1 AND s.enabled=1 AND COALESCE(n.missing_since,'')=''`
	var args []any
	if scope.SourceID != 0 {
		q += ` AND n.source_id=?`
		args = append(args, scope.SourceID)
	}
	if explicit {
		q += ` AND n.id IN (` + placeholders(len(ids)) + `)`
		args = append(args, idArgs(ids)...)
	}
	limit := scope.Limit
	if limit == 0 {
		limit = DefaultLimit
		if explicit {
			limit = len(ids)
		}
	}
	q += ` ORDER BY n.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, storageError(ctx, err)
	}
	out := make([]Target, 0)
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.SourceID, &t.RawLink, &t.NodeHash, &t.LinkVersion); err != nil {
			rows.Close()
			return nil, storageError(ctx, err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, storageError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return nil, storageError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, storageError(ctx, err)
	}
	return out, nil
}

// Check preserves the old synchronous API and its legacy limit normalization.
// It uses the same per-Service guard, scope filtering, versioning and executor.
func (s *Service) Check(limit int) ([]Result, error) {
	if limit <= 0 || limit > MaxLimit {
		limit = DefaultLimit
	}
	return s.CheckContext(context.Background(), Scope{Limit: limit}, nil)
}

func (s *Service) CheckContext(ctx context.Context, scope Scope, progress func(Result)) ([]Result, error) {
	if err := s.beginCheck(ctx); err != nil {
		return nil, err
	}
	defer s.checking.Store(false)
	targets, err := s.SelectTargets(ctx, scope)
	if err != nil {
		return nil, err
	}
	return s.checkTargets(ctx, targets, progress)
}

func (s *Service) CheckTargetsContext(ctx context.Context, targets []Target, progress func(Result)) ([]Result, error) {
	if err := s.beginCheck(ctx); err != nil {
		return nil, err
	}
	defer s.checking.Store(false)
	return s.checkTargets(ctx, append([]Target(nil), targets...), progress)
}

func (s *Service) beginCheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.checking.CompareAndSwap(false, true) {
		return ErrCheckInProgress
	}
	return nil
}

func (s *Service) checkTargets(ctx context.Context, targets []Target, progress func(Result)) ([]Result, error) {
	if len(targets) > MaxLimit {
		return nil, ErrInvalidScope
	}
	seen := make(map[int64]bool, len(targets))
	for _, t := range targets {
		generation, err := strconv.ParseInt(t.LinkVersion, 10, 64)
		if t.ID <= 0 || t.SourceID <= 0 || err != nil || generation <= 0 || seen[t.ID] {
			return nil, ErrInvalidScope
		}
		seen[t.ID] = true
	}
	if err := s.ExpireContext(ctx); err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		current, err := s.targetCurrent(ctx, t)
		if err != nil {
			return out, err
		}
		start := time.Now()
		r := resultFor(CodeTargetChanged)
		if current {
			r = executeSafely(s.executor, ctx, t)
		}
		// Cancellation is not negative evidence. Do not persist or emit an
		// unfinished observation, even if an injected executor ignored ctx.
		if err := ctx.Err(); err != nil {
			return out, err
		}
		r = normalizeObservation(r)
		r.NodeID, r.NodeHash, r.LinkVersion = t.ID, t.NodeHash, t.LinkVersion
		r.ElapsedMS = time.Since(start).Milliseconds()
		now := s.now().UTC()
		r.CheckedAt = now.Format(time.RFC3339Nano)
		if current {
			saved, err := s.saveContext(ctx, t, r, now)
			if err != nil {
				return out, err
			}
			if !saved {
				stale := resultFor(CodeTargetChanged)
				stale.NodeID, stale.NodeHash, stale.LinkVersion = r.NodeID, r.NodeHash, r.LinkVersion
				stale.CheckedAt, stale.ElapsedMS = r.CheckedAt, r.ElapsedMS
				r = stale
			}
		}
		out = append(out, r)
		if progress != nil {
			progress(r) // synchronous, after conditional persistence
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func executeSafely(executor Executor, ctx context.Context, t Target) (r Result) {
	defer func() {
		if recover() != nil {
			r = resultFor(CodeExecutorError)
		}
	}()
	return executor.Check(ctx, t)
}

type resultInfo struct{ status, class, message string }

// All published errors are drawn from this closed, static vocabulary. Kernel
// output, converter errors, raw links and url.Error strings are never returned.
var resultCodes = map[string]resultInfo{
	CodeOK:               {StatusOK, "", ""},
	CodeRemoteError:      {StatusFail, FailureRemote, "Remote proxy check failed."},
	CodeRemoteTimeout:    {StatusFail, FailureRemote, "Remote proxy check timed out."},
	CodeUnsupportedLink:  {StatusUnknown, FailureConfig, "Proxy link is unsupported or malformed."},
	CodeKernelMissing:    {StatusUnknown, FailureKernel, "Mihomo is not installed or executable."},
	CodeConfigInvalid:    {StatusUnknown, FailureConfig, "Proxy configuration validation failed."},
	CodeConfigTimeout:    {StatusUnknown, FailureKernel, "Proxy configuration validation timed out."},
	CodeConfigWrite:      {StatusUnknown, FailureLocal, "Private proxy configuration could not be written."},
	CodeTempDir:          {StatusUnknown, FailureLocal, "Private check directory could not be created."},
	CodeTempCleanup:      {StatusUnknown, FailureLocal, "Private check directory could not be removed."},
	CodePortUnavailable:  {StatusUnknown, FailureLocal, "A local proxy port could not be allocated."},
	CodeKernelStart:      {StatusUnknown, FailureKernel, "Mihomo could not be started."},
	CodeKernelExited:     {StatusUnknown, FailureKernel, "Mihomo exited before the check completed."},
	CodeKernelTimeout:    {StatusUnknown, FailureKernel, "Mihomo check runtime expired."},
	CodeProxyNotReady:    {StatusUnknown, FailureKernel, "Local proxy did not become ready."},
	CodeProxyUnavailable: {StatusUnknown, FailureKernel, "Local proxy is unavailable."},
	CodeProxyAuth:        {StatusUnknown, FailureKernel, "Local proxy authentication failed."},
	CodeTargetInvalid:    {StatusUnknown, FailureTarget, "HTTPS check target is invalid."},
	CodeTargetTLS:        {StatusUnknown, FailureTarget, "HTTPS check target TLS validation failed."},
	CodeTargetStatus:     {StatusUnknown, FailureTarget, "HTTPS check target did not return exactly 204."},
	CodeTargetChanged:    {StatusUnknown, FailureTarget, "Node changed or became ineligible; check result discarded."},
	CodeCancelled:        {StatusUnknown, FailureCancelled, "Connectivity check cancelled."},
	CodeDeadline:         {StatusUnknown, FailureCancelled, "Connectivity check deadline exceeded."},
	CodeExecutorError:    {StatusUnknown, FailureLocal, "Connectivity executor returned an invalid result."},
}

func resultFor(code string) Result {
	info, ok := resultCodes[code]
	if !ok {
		code, info = CodeExecutorError, resultCodes[CodeExecutorError]
	}
	return Result{Status: info.status, Code: code, FailureClass: info.class, LastError: info.message}
}

func normalizeObservation(r Result) Result {
	code := r.Code
	if r.Status == StatusOK && (code == "" || code == CodeOK) {
		out := resultFor(CodeOK)
		if r.LatencyMS != nil && *r.LatencyMS >= 0 {
			latency := *r.LatencyMS
			out.LatencyMS = &latency
		}
		return out
	}
	// A known local/config/kernel/target code always wins over an
	// accidentally supplied fail/remote label from an executor.
	if info, ok := resultCodes[code]; ok && info.status == StatusUnknown {
		return resultFor(code)
	}
	if r.Status == StatusFail && r.FailureClass == FailureRemote {
		if code != CodeRemoteError && code != CodeRemoteTimeout {
			code = CodeRemoteError
		}
		return resultFor(code)
	}
	return resultFor(CodeExecutorError)
}

func cancelledResult(ctx context.Context) Result {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return resultFor(CodeDeadline)
	}
	return resultFor(CodeCancelled)
}

func storageError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrStorage
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }

func idArgs(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}
