package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/services/connectivity"
	"github.com/Spittingjiu/subgo/internal/services/jobs"
	"github.com/Spittingjiu/subgo/internal/services/node"
	"github.com/Spittingjiu/subgo/internal/services/source"
	"github.com/gin-gonic/gin"
)

type taskRequestError struct{ message string }

func (e *taskRequestError) Error() string { return e.message }
func taskInputError(message string) error { return &taskRequestError{message: message} }

func (s *Server) registerTaskRoutes(api *gin.RouterGroup) {
	tasks := api.Group("/tasks", s.taskOriginGuard())
	tasks.POST("/sync", s.taskSync)
	tasks.POST("/connectivity", s.taskConnectivity)
	tasks.GET("", s.taskList)
	tasks.GET("/:id", s.taskGet)
	tasks.POST("/:id/cancel", s.taskCancel)
	api.POST("/nodes/bulk-toggle", s.taskOriginGuard(), s.bulkToggleNodes)
}

// This narrow guard makes the new mutation endpoints safe before the parent
// integrates the security lane's management-wide Origin/Fetch-Metadata hook.
// It permits cookie-authenticated CLI clients without browser Origin headers.
func (s *Server) taskOriginGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		if strings.EqualFold(c.GetHeader("Sec-Fetch-Site"), "cross-site") {
			c.AbortWithStatusJSON(403, gin.H{"ok": false, "error": "cross-origin mutation rejected"})
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" {
			u, err := url.Parse(origin)
			scheme := "http"
			if isHTTPS(c) {
				scheme = "https"
			}
			if base, err := url.Parse(s.cfg.BaseURL); err == nil && base.Scheme == "https" {
				scheme = "https"
			}
			expected, _ := url.Parse(scheme + "://" + c.Request.Host)
			if err != nil || expected == nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !strings.EqualFold(u.Scheme, expected.Scheme) || !sameTaskOriginHost(u, expected) {
				c.AbortWithStatusJSON(403, gin.H{"ok": false, "error": "cross-origin mutation rejected"})
				return
			}
		}
		c.Next()
	}
}

func sameTaskOriginHost(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return a.Hostname() != "" && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// Do not let bad JSON, null, unknown keys, trailing values or missing booleans
// silently turn into a default all-host operation.
func decodeTaskJSON(c *gin.Context, destination any, allowEmpty bool) error {
	const maxBody = 64 << 10
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return taskInputError("invalid or oversized JSON body")
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 && allowEmpty {
		body = []byte("{}")
	}
	if len(body) == 0 || body[0] != '{' {
		return taskInputError("JSON object required")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return taskInputError("invalid JSON fields")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return taskInputError("single JSON object required")
	}
	return nil
}

func decodeTaskIDs(raw json.RawMessage, field string) ([]int64, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, taskInputError(field + " must be an explicit ID array, not null")
	}
	var ids []int64
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, taskInputError(field + " must contain real integer IDs")
	}
	if ids == nil {
		ids = []int64{}
	}
	return ids, nil
}

func decodeConnectivityScope(c *gin.Context, legacy bool) (connectivity.Scope, error) {
	var request struct {
		NodeIDs  json.RawMessage `json:"node_ids"`
		SourceID json.RawMessage `json:"source_id"`
		Limit    json.RawMessage `json:"limit"`
	}
	if err := decodeTaskJSON(c, &request, legacy); err != nil {
		return connectivity.Scope{}, err
	}
	ids, err := decodeTaskIDs(request.NodeIDs, "node_ids")
	if err != nil {
		return connectivity.Scope{}, err
	}
	scope := connectivity.Scope{NodeIDs: ids}
	if len(request.SourceID) > 0 {
		if bytes.Equal(bytes.TrimSpace(request.SourceID), []byte("null")) || json.Unmarshal(request.SourceID, &scope.SourceID) != nil || scope.SourceID <= 0 {
			return scope, taskInputError("source_id must be a positive real ID")
		}
	} else if legacy {
		raw := c.Query("source_id")
		if raw == "" {
			raw = c.Query("sourceId")
		}
		if raw != "" {
			id, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || id <= 0 {
				return scope, taskInputError("invalid source ID")
			}
			scope.SourceID = id
		}
	}
	if len(request.Limit) > 0 {
		if bytes.Equal(bytes.TrimSpace(request.Limit), []byte("null")) || json.Unmarshal(request.Limit, &scope.Limit) != nil || scope.Limit <= 0 || scope.Limit > 200 {
			return scope, taskInputError("limit must be between 1 and 200")
		}
	} else if legacy && c.Query("limit") != "" {
		limit, err := strconv.Atoi(c.Query("limit"))
		if err != nil || limit <= 0 || limit > 200 {
			return scope, taskInputError("limit must be between 1 and 200")
		}
		scope.Limit = limit
	}
	return scope, nil
}

func (s *Server) taskSync(c *gin.Context) {
	var request struct {
		SourceIDs json.RawMessage `json:"source_ids"`
	}
	if err := decodeTaskJSON(c, &request, false); err != nil {
		taskJSONError(c, err)
		return
	}
	ids, err := decodeTaskIDs(request.SourceIDs, "source_ids")
	if err != nil {
		taskJSONError(c, err)
		return
	}
	task, err := s.taskSvc.SubmitSync(c.Request.Context(), ids, "manual")
	if err != nil {
		taskJSONError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"ok": true, "task": task})
}

func (s *Server) taskConnectivity(c *gin.Context) {
	scope, err := decodeConnectivityScope(c, false)
	if err != nil {
		taskJSONError(c, err)
		return
	}
	task, err := s.taskSvc.SubmitConnectivity(c.Request.Context(), scope, "manual")
	if err != nil {
		taskJSONError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"ok": true, "task": task})
}

func (s *Server) taskList(c *gin.Context) {
	snapshot, err := s.taskSvc.List(c.Request.Context())
	if err != nil {
		taskJSONError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"ok": true, "tasks": snapshot.Tasks, "active": snapshot.Active, "recent": snapshot.Recent,
		"recent_success": snapshot.RecentSuccess, "history_limit": snapshot.HistoryLimit,
		"schedule": gin.H{"source_sync_enabled": s.cfg.SourceSyncInterval > 0, "source_sync_interval_ms": s.cfg.SourceSyncInterval.Milliseconds(), "automatic_connectivity_enabled": false}})
}

func validTaskID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s *Server) taskGet(c *gin.Context) {
	id := c.Param("id")
	if !validTaskID(id) {
		taskJSONError(c, taskInputError("invalid task ID"))
		return
	}
	task, err := s.taskSvc.Get(c.Request.Context(), id)
	if err != nil {
		taskJSONError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"ok": true, "task": task})
}

func (s *Server) taskCancel(c *gin.Context) {
	id := c.Param("id")
	if !validTaskID(id) {
		taskJSONError(c, taskInputError("invalid task ID"))
		return
	}
	var request struct{}
	if err := decodeTaskJSON(c, &request, true); err != nil {
		taskJSONError(c, err)
		return
	}
	task, err := s.taskSvc.Cancel(c.Request.Context(), id)
	if err != nil {
		taskJSONError(c, err)
		return
	}
	c.JSON(200, gin.H{"ok": true, "task": task})
}

func (s *Server) bulkToggleNodes(c *gin.Context) {
	var request struct {
		NodeIDs json.RawMessage `json:"node_ids"`
		Enabled *bool           `json:"enabled"`
	}
	if err := decodeTaskJSON(c, &request, false); err != nil {
		taskJSONError(c, err)
		return
	}
	if request.Enabled == nil || len(request.NodeIDs) == 0 {
		taskJSONError(c, taskInputError("node_ids and explicit enabled boolean required"))
		return
	}
	ids, err := decodeTaskIDs(request.NodeIDs, "node_ids")
	if err != nil {
		taskJSONError(c, err)
		return
	}
	n, err := s.nodes.BulkToggleContext(c.Request.Context(), ids, *request.Enabled)
	if err != nil {
		taskJSONError(c, err)
		return
	}
	c.JSON(200, gin.H{"ok": true, "updated": n})
}

func safeTaskError(err error) string {
	var input *taskRequestError
	var conflict *jobs.ConflictError
	switch {
	case errors.As(err, &input):
		return input.Error()
	case errors.As(err, &conflict):
		return conflict.Error()
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, jobs.ErrClosed), errors.Is(err, jobs.ErrQueueFull), errors.Is(err, jobs.ErrStateStorage):
		return err.Error()
	case errors.Is(err, source.ErrInvalidScope), errors.Is(err, connectivity.ErrInvalidScope):
		return "invalid task scope"
	case errors.Is(err, source.ErrSyncInProgress), errors.Is(err, connectivity.ErrCheckInProgress):
		return "executor already running"
	case errors.Is(err, node.ErrInvalidNodeIDs):
		return node.ErrInvalidNodeIDs.Error()
	case errors.Is(err, sql.ErrNoRows):
		return "requested object not found"
	case errors.Is(err, context.Canceled):
		return "request cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "request timed out"
	default:
		return "task request failed"
	}
}

func taskJSONError(c *gin.Context, err error) {
	status := 500
	var input *taskRequestError
	var conflict *jobs.ConflictError
	switch {
	case errors.As(err, &input), errors.Is(err, source.ErrInvalidScope), errors.Is(err, connectivity.ErrInvalidScope), errors.Is(err, node.ErrInvalidNodeIDs):
		status = 400
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, sql.ErrNoRows):
		status = 404
	case errors.As(err, &conflict), errors.Is(err, source.ErrSyncInProgress), errors.Is(err, connectivity.ErrCheckInProgress):
		status = 409
	case errors.Is(err, jobs.ErrQueueFull):
		status = 429
		c.Header("Retry-After", "3")
	case errors.Is(err, jobs.ErrClosed), errors.Is(err, jobs.ErrStateStorage):
		status = 503
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status = 504
	}
	body := gin.H{"ok": false, "error": safeTaskError(err)}
	if conflict != nil {
		body["task_id"] = conflict.TaskID
	}
	c.JSON(status, body)
}

func taskFailureMessage(task jobs.Task) string {
	if task.Error != "" {
		return task.Error
	}
	for _, result := range task.Results {
		if result.Error != "" {
			return result.Error
		}
	}
	return task.Message
}

func (s *Server) waitLegacyTask(ctx context.Context, id string) (jobs.Task, error) {
	task, err := s.taskSvc.Wait(ctx, id)
	if err != nil && ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = s.taskSvc.Cancel(cleanup, id)
		_, _ = s.taskSvc.Wait(cleanup, id)
	}
	return task, err
}

func (s *Server) runSyncTask(ctx context.Context, ids []int64, trigger string) (jobs.Task, error) {
	task, err := s.taskSvc.SubmitSync(ctx, ids, trigger)
	if err != nil {
		return task, err
	}
	return s.waitLegacyTask(ctx, task.ID)
}

func legacySyncResults(task jobs.Task) map[int64]string {
	out := map[int64]string{}
	for _, result := range task.Results {
		if result.SourceID <= 0 {
			continue
		}
		if result.Status == "ok" {
			out[result.SourceID] = "ok"
		} else {
			out[result.SourceID] = result.Message
		}
	}
	if task.Error != "" {
		out[-1] = task.Error
	}
	return out
}

func legacyConnectivityResults(task jobs.Task) []connectivity.Result {
	out := make([]connectivity.Result, 0, len(task.Results))
	for _, result := range task.Results {
		status := result.Status
		if status == "skipped" || status == "cancelled" {
			status = "unknown"
		}
		out = append(out, connectivity.Result{NodeID: result.NodeID, Status: status, LatencyMS: result.LatencyMS, LastError: result.Error, CheckedAt: result.CheckedAt, Code: result.Code, ElapsedMS: result.ElapsedMS})
	}
	return out
}

func (s *Server) startBackground(fn func()) {
	s.backgroundWG.Add(1)
	go func() { defer s.backgroundWG.Done(); fn() }()
}

// Expiration maintains the legacy effective status table; it is not a scan and
// never starts a kernel or a source request. Public rendering expires once more
// immediately before the existing subscription query, to enforce the TTL.
func (s *Server) connectivityExpiryScheduler() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if s.ctx.Err() != nil {
			return
		}
		_ = s.conn.ExpireContext(s.ctx)
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) ensureFreshConnectivity(c *gin.Context) bool {
	if err := s.conn.ExpireContext(c.Request.Context()); err != nil {
		c.String(503, "connectivity state unavailable")
		return false
	}
	return true
}
