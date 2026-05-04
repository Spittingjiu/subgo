package connectivity

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Spittingjiu/subgo/internal/subconv"
)

type Service struct{ db *sql.DB }
type Result struct {
	NodeID    int64  `json:"node_id"`
	Status    string `json:"status"`
	LatencyMS *int64 `json:"latency_ms"`
	LastError string `json:"last_error"`
	CheckedAt string `json:"checked_at"`
}

func New(db *sql.DB) *Service { return &Service{db: db} }
func (s *Service) EnsureSchema() {
	s.db.Exec(`CREATE TABLE IF NOT EXISTS node_connectivity (node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, status TEXT NOT NULL, latency_ms INTEGER, last_error TEXT NOT NULL DEFAULT '', checked_at TEXT NOT NULL)`)
}
func (s *Service) List() ([]Result, error) {
	s.EnsureSchema()
	rows, err := s.db.Query(`SELECT node_id,status,latency_ms,last_error,checked_at FROM node_connectivity ORDER BY checked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var r Result
		var lat sql.NullInt64
		if err := rows.Scan(&r.NodeID, &r.Status, &lat, &r.LastError, &r.CheckedAt); err != nil {
			return nil, err
		}
		if lat.Valid {
			r.LatencyMS = &lat.Int64
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Service) Check(limit int) ([]Result, error) {
	s.EnsureSchema()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id,raw_link FROM nodes WHERE enabled=1 ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type job struct {
		id  int64
		raw string
	}
	var jobs []job
	for rows.Next() {
		var j job
		_ = rows.Scan(&j.id, &j.raw)
		jobs = append(jobs, j)
	}
	ch := make(chan job)
	out := make(chan Result)
	var wg sync.WaitGroup
	workers := 8
	if len(jobs) < workers {
		workers = len(jobs)
	}
	if workers == 0 {
		return []Result{}, nil
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				out <- s.checkOne(j.id, j.raw)
			}
		}()
	}
	go func() {
		for _, j := range jobs {
			ch <- j
		}
		close(ch)
		wg.Wait()
		close(out)
	}()
	var res []Result
	for r := range out {
		res = append(res, r)
		s.save(r)
	}
	return res, nil
}
func (s *Service) checkOne(id int64, raw string) Result {
	p := subconv.ParseRawLink(raw)
	now := time.Now().UTC().Format(time.RFC3339)
	if p.Host == "" || p.Port == 0 {
		return Result{NodeID: id, Status: "unknown", LastError: "missing host/port", CheckedAt: now}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.Host, fmtPort(p.Port)))
	if err != nil {
		return Result{NodeID: id, Status: "fail", LastError: err.Error(), CheckedAt: now}
	}
	_ = conn.Close()
	ms := time.Since(start).Milliseconds()
	return Result{NodeID: id, Status: "ok", LatencyMS: &ms, CheckedAt: now}
}
func (s *Service) save(r Result) {
	var lat any = nil
	if r.LatencyMS != nil {
		lat = *r.LatencyMS
	}
	_, _ = s.db.Exec(`INSERT INTO node_connectivity(node_id,status,latency_ms,last_error,checked_at) VALUES(?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET status=excluded.status,latency_ms=excluded.latency_ms,last_error=excluded.last_error,checked_at=excluded.checked_at`, r.NodeID, r.Status, lat, r.LastError, r.CheckedAt)
}
func fmtPort(p int) string { return strconv.Itoa(p) }
