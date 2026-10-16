package logs

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Kinds of log the panel can show.
const (
	KindSystem       = "system"
	KindSubscription = "subscription"
	KindAudit        = "audit"
)

const (
	maxMessageLen = 600
	maxDetailLen  = 4000
	maxPageSize   = 500
	maxExportRows = 5000
)

// SystemRow is one line of 运行日志.
type SystemRow struct {
	ID        int64  `json:"id"`
	Level     string `json:"level"`
	Scope     string `json:"scope"`
	Message   string `json:"message"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"created_at"`
}

// SubscriptionRow is one subscription fetch, shown as 访问日志.
type SubscriptionRow struct {
	ID               int64  `json:"id"`
	Token            string `json:"token"`
	SubscriptionID   int64  `json:"subscription_id"`
	SubscriptionName string `json:"subscription_name"`
	RouteType        string `json:"route_type"`
	ClientIP         string `json:"client_ip"`
	UserAgent        string `json:"user_agent"`
	Device           string `json:"device"`
	Icon             string `json:"icon"`
	CreatedAt        string `json:"created_at"`
}

// AuditRow is one privileged action performed through the panel.
type AuditRow struct {
	ID         int64  `json:"id"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Detail     string `json:"detail"`
	CreatedAt  string `json:"created_at"`
}

// Stats summarises how much history is currently stored.
type Stats struct {
	System       int `json:"system"`
	Subscription int `json:"subscription"`
	Audit        int `json:"audit"`
}

// Filter is the shared query shape behind all three views.
type Filter struct {
	Q              string
	Scope          string
	Level          string
	SubscriptionID int64
	Limit          int
	Offset         int
}

func (f Filter) normalized(defLimit int) Filter {
	if f.Limit <= 0 {
		f.Limit = defLimit
	}
	if f.Limit > maxPageSize {
		f.Limit = maxPageSize
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	f.Q = strings.TrimSpace(f.Q)
	f.Scope = strings.TrimSpace(f.Scope)
	f.Level = strings.TrimSpace(f.Level)
	return f
}

type entry struct {
	level   string
	scope   string
	message string
	detail  string
}

// Service owns the system log queue and every log query.
type Service struct {
	db    *sql.DB
	queue chan entry

	stopOnce sync.Once
	done     chan struct{}
	stopped  chan struct{}
}

func New(db *sql.DB) *Service {
	s := &Service{db: db, queue: make(chan entry, 2048), done: make(chan struct{}), stopped: make(chan struct{})}
	go s.worker()
	return s
}

// Stop drains the queue and stops the writer. Call it before closing the DB.
// The queue itself is never closed: a line that arrives after Stop is dropped
// instead of panicking, so shutdown cannot be taken down by its own logging.
func (s *Service) Stop() {
	s.stopOnce.Do(func() { close(s.done) })
	select {
	case <-s.stopped:
	case <-time.After(2 * time.Second):
	}
}

// drain collects whatever is still queued, so a clean shutdown does not lose
// the last lines it was asked to record.
func (s *Service) drain() []entry {
	batch := []entry{}
	for {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
		default:
			return batch
		}
	}
}

func (s *Service) Info(scope, message string)  { s.Write("info", scope, message, "") }
func (s *Service) Warn(scope, message string)  { s.Write("warn", scope, message, "") }
func (s *Service) Error(scope, message string) { s.Write("error", scope, message, "") }

// Write queues one line. It never blocks and never returns an error: logging
// must not be able to fail a request, and dropping a line is better than
// stalling a subscription fetch. The worker drains the queue in batches.
func (s *Service) Write(level, scope, message, detail string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "app"
	}
	select {
	case s.queue <- entry{level: normalizeLevel(level), scope: scope, message: clip(message, maxMessageLen), detail: clip(detail, maxDetailLen)}:
	default:
	}
}

func (s *Service) worker() {
	defer close(s.stopped)
	for {
		var first entry
		select {
		case first = <-s.queue:
		case <-s.done:
			s.flush(s.drain())
			return
		}
		batch := []entry{first}
	batchFull:
		for len(batch) < 64 {
			select {
			case more := <-s.queue:
				batch = append(batch, more)
			default:
				break batchFull
			}
		}
		s.flush(batch)
	}
}

// flush intentionally swallows every error: there is nowhere left to report a
// failure that would not recurse back into this writer.
func (s *Service) flush(batch []entry) {
	if len(batch) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO system_logs(level,scope,message,detail,created_at) VALUES(?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, e := range batch {
		_, _ = stmt.Exec(e.level, e.scope, e.message, e.detail, now)
	}
	_ = stmt.Close()
	_ = tx.Commit()
}

var (
	logTimePrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? `)
	logScopeTag   = regexp.MustCompile(`^\[([a-z0-9._-]+)\]`)
	scopeAliases  = map[string]string{
		"clash-template":        "template",
		"source-sync":           "sync",
		"source-sync-scheduler": "sync",
		"migration":             "migration",
		"kernel":                "kernel",
	}
)

// Sink adapts the process logger to this service, so lines that used to reach
// only journald (template refresh, source sync results) are visible in the
// panel too. It must never log itself: a database failure here would recurse.
func (s *Service) Sink() io.Writer { return sink{svc: s} }

type sink struct{ svc *Service }

func (w sink) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		line = strings.TrimSpace(logTimePrefix.ReplaceAllString(line, ""))
		if line == "" {
			continue
		}
		w.svc.Write(levelForLine(line), scopeForLine(line), line, "")
	}
	return len(p), nil
}

func levelForLine(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "panic") || strings.Contains(l, "fatal"):
		return "error"
	case strings.Contains(l, "error") || strings.Contains(l, "failed") || strings.Contains(l, "failure") || strings.Contains(l, "rejected"):
		return "error"
	case strings.Contains(l, "warn"):
		return "warn"
	}
	return "info"
}

func scopeForLine(line string) string {
	m := logScopeTag.FindStringSubmatch(line)
	if m == nil {
		return "app"
	}
	if alias, ok := scopeAliases[m[1]]; ok {
		return alias
	}
	return m[1]
}

// DeviceLabel turns a subscription User-Agent into something scannable, such as
// "Clash Verge · Windows". It returns an empty string for clients it does not
// recognise.
func DeviceLabel(ua string) string {
	l := strings.ToLower(ua)
	client := ""
	// Order matters: the specific clients come before the bare "clash" fallback,
	// and both spellings of Clash Verge are covered because its user agent has
	// changed between releases.
	switch {
	case strings.Contains(l, "clash-verge"), strings.Contains(l, "clash verge"):
		client = "Clash Verge"
	case strings.Contains(l, "clashforwindows"), strings.Contains(l, "clash for windows"):
		client = "Clash for Windows"
	case strings.Contains(l, "clashx"):
		client = "ClashX"
	case strings.Contains(l, "clash.meta"):
		client = "Clash.Meta"
	case strings.Contains(l, "flclash"):
		client = "FlClash"
	case strings.Contains(l, "stash"):
		client = "Stash"
	case strings.Contains(l, "shadowrocket"):
		client = "Shadowrocket"
	case strings.Contains(l, "surge"):
		client = "Surge"
	case strings.Contains(l, "loon"):
		client = "Loon"
	case strings.Contains(l, "quantumult"):
		client = "Quantumult"
	case strings.Contains(l, "hiddify"):
		client = "Hiddify"
	case strings.Contains(l, "nekobox"):
		client = "NekoBox"
	case strings.Contains(l, "karing"):
		client = "Karing"
	case strings.Contains(l, "v2rayng"):
		client = "v2rayNG"
	case strings.Contains(l, "sing-box"), strings.Contains(l, "sfa/"), strings.Contains(l, "sfi/"):
		client = "sing-box"
	case strings.Contains(l, "clash"):
		client = "Clash"
	case strings.Contains(l, "mozilla"):
		client = "浏览器"
	}
	system := ""
	switch {
	case strings.Contains(l, "iphone"):
		system = "iPhone"
	case strings.Contains(l, "ipad"):
		system = "iPad"
	case strings.Contains(l, "android"):
		system = "Android"
	case strings.Contains(l, "macintosh") || strings.Contains(l, "darwin"):
		system = "macOS"
	case strings.Contains(l, "windows"):
		system = "Windows"
	case strings.Contains(l, "linux"):
		system = "Linux"
	case strings.Contains(l, "curl"), strings.Contains(l, "wget"):
		system = "命令行"
	}
	switch {
	case client != "" && system != "":
		// Avoid a label like "Clash for Windows · Windows".
		if strings.Contains(strings.ToLower(client), strings.ToLower(system)) {
			return client
		}
		return client + " · " + system
	case client != "":
		return client
	default:
		return system
	}
}

// DeviceIcon is the emoji the 访问日志 table puts in front of the device label.
func DeviceIcon(device string) string {
	switch {
	case strings.Contains(device, "iPhone"), strings.Contains(device, "iPad"), strings.Contains(device, "macOS"):
		return "🍎"
	case strings.Contains(device, "Android"):
		return "🤖"
	case strings.Contains(device, "Windows"):
		return "🪟"
	case strings.Contains(device, "Linux"):
		return "🐧"
	case strings.Contains(device, "命令行"):
		return "💻"
	}
	return "🌐"
}

func (s *Service) System(f Filter) ([]SystemRow, int, error) {
	f = f.normalized(100)
	where := []string{"1=1"}
	args := []any{}
	if f.Scope != "" && f.Scope != "all" {
		where = append(where, "scope=?")
		args = append(args, f.Scope)
	}
	if f.Level != "" && f.Level != "all" {
		where = append(where, "level=?")
		args = append(args, f.Level)
	}
	if f.Q != "" {
		where = append(where, "(message LIKE ? OR detail LIKE ?)")
		like := "%" + f.Q + "%"
		args = append(args, like, like)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.count(`SELECT COUNT(*) FROM system_logs WHERE `+clause, args)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,level,scope,message,detail,created_at FROM system_logs WHERE `+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`, withPage(args, f)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SystemRow{}
	for rows.Next() {
		var r SystemRow
		if err := rows.Scan(&r.ID, &r.Level, &r.Scope, &r.Message, &r.Detail, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Service) Subscriptions(f Filter) ([]SubscriptionRow, int, error) {
	f = f.normalized(100)
	where := []string{"1=1"}
	args := []any{}
	if f.SubscriptionID > 0 {
		where = append(where, "subscription_id=?")
		args = append(args, f.SubscriptionID)
	}
	if f.Q != "" {
		where = append(where, "(subscription_name LIKE ? OR client_ip LIKE ? OR user_agent LIKE ? OR token LIKE ?)")
		like := "%" + f.Q + "%"
		args = append(args, like, like, like, like)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.count(`SELECT COUNT(*) FROM subscription_logs WHERE `+clause, args)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,token,subscription_id,subscription_name,route_type,client_ip,user_agent,created_at FROM subscription_logs WHERE `+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`, withPage(args, f)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SubscriptionRow{}
	for rows.Next() {
		var r SubscriptionRow
		if err := rows.Scan(&r.ID, &r.Token, &r.SubscriptionID, &r.SubscriptionName, &r.RouteType, &r.ClientIP, &r.UserAgent, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		r.Device = DeviceLabel(r.UserAgent)
		r.Icon = DeviceIcon(r.Device)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Service) Audits(f Filter) ([]AuditRow, int, error) {
	f = f.normalized(100)
	where := []string{"1=1"}
	args := []any{}
	if f.Q != "" {
		where = append(where, "(action LIKE ? OR target_type LIKE ? OR target_id LIKE ? OR detail LIKE ?)")
		like := "%" + f.Q + "%"
		args = append(args, like, like, like, like)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.count(`SELECT COUNT(*) FROM audit_logs WHERE `+clause, args)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id,action,target_type,target_id,detail,created_at FROM audit_logs WHERE `+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`, withPage(args, f)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditRow{}
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.Action, &r.TargetType, &r.TargetID, &r.Detail, &r.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Service) Stats() (Stats, error) {
	var st Stats
	for table, dst := range map[string]*int{
		"system_logs":       &st.System,
		"subscription_logs": &st.Subscription,
		"audit_logs":        &st.Audit,
	} {
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(dst); err != nil {
			return st, err
		}
	}
	return st, nil
}

// ScopeCount is one row of the 模块 filter in the panel.
type ScopeCount struct {
	Scope string `json:"scope"`
	Count int    `json:"count"`
}

// Scopes lists the modules that have produced runtime log lines, most active
// first, so the panel can offer a module filter without hard-coding names.
func (s *Service) Scopes() ([]ScopeCount, error) {
	rows, err := s.db.Query(`SELECT scope, COUNT(*) FROM system_logs GROUP BY scope ORDER BY COUNT(*) DESC, scope ASC LIMIT 40`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopeCount{}
	for rows.Next() {
		var sc ScopeCount
		if err := rows.Scan(&sc.Scope, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// Clear removes every row of one kind. The table name comes from a fixed map so
// a query parameter can never reach the SQL string.
func (s *Service) Clear(kind string) (int64, error) {
	table, ok := kindTable(kind)
	if !ok {
		return 0, errors.New("unknown log kind")
	}
	res, err := s.db.Exec(`DELETE FROM ` + table)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Prune drops rows older than days. created_at is RFC3339 in UTC, so comparing
// the strings is already chronological. days <= 0 keeps everything.
func (s *Service) Prune(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	var removed int64
	for _, table := range []string{"system_logs", "subscription_logs", "audit_logs"} {
		res, err := s.db.Exec(`DELETE FROM `+table+` WHERE created_at < ?`, cutoff)
		if err != nil {
			return removed, err
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	return removed, nil
}

// Export streams one view as CSV, newest first. The leading BOM keeps Excel from
// mangling the Chinese headers.
func (s *Service) Export(kind string, f Filter, w io.Writer) error {
	f.Limit = maxExportRows
	f.Offset = 0
	if _, err := io.WriteString(w, "\ufeff"); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	write := func(header []string, rows [][]string) error {
		if err := cw.Write(header); err != nil {
			return err
		}
		for _, r := range rows {
			if err := cw.Write(r); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	}
	switch kind {
	case KindSystem:
		rows, _, err := s.System(f)
		if err != nil {
			return err
		}
		out := make([][]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, []string{r.CreatedAt, r.Level, r.Scope, r.Message, r.Detail})
		}
		return write([]string{"时间", "级别", "模块", "内容", "详情"}, out)
	case KindSubscription:
		rows, _, err := s.Subscriptions(f)
		if err != nil {
			return err
		}
		out := make([][]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, []string{r.CreatedAt, r.SubscriptionName, r.Token, r.RouteType, r.Device, r.ClientIP, r.UserAgent})
		}
		return write([]string{"时间", "订阅", "Token", "类型", "设备", "IP", "User-Agent"}, out)
	case KindAudit:
		rows, _, err := s.Audits(f)
		if err != nil {
			return err
		}
		out := make([][]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, []string{r.CreatedAt, r.Action, r.TargetType, r.TargetID, r.Detail})
		}
		return write([]string{"时间", "操作", "对象类型", "对象", "详情"}, out)
	}
	return errors.New("unknown log kind")
}

func (s *Service) count(query string, args []any) (int, error) {
	var n int
	err := s.db.QueryRow(query, args...).Scan(&n)
	return n, err
}

// withPage appends LIMIT/OFFSET without mutating the caller's slice.
func withPage(args []any, f Filter) []any {
	out := make([]any, 0, len(args)+2)
	out = append(out, args...)
	return append(out, f.Limit, f.Offset)
}

func kindTable(kind string) (string, bool) {
	switch kind {
	case KindSystem:
		return "system_logs", true
	case KindSubscription:
		return "subscription_logs", true
	case KindAudit:
		return "audit_logs", true
	}
	return "", false
}

func normalizeLevel(l string) string {
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "warn", "warning":
		return "warn"
	case "error", "err", "fatal", "panic":
		return "error"
	default:
		return "info"
	}
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
