package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Spittingjiu/subgo/internal/config"
	"github.com/Spittingjiu/subgo/internal/db"
	"github.com/Spittingjiu/subgo/internal/services/auth"
	"github.com/Spittingjiu/subgo/internal/services/node"
	"github.com/Spittingjiu/subgo/internal/services/subscription"
	"github.com/gin-gonic/gin"
)

const Version = "0.2.0-dev"

type Server struct {
	cfg    config.Config
	db     *db.DB
	auth   *auth.Service
	nodes  *node.Service
	subs   *subscription.Service
	router *gin.Engine
}

func New(cfg config.Config) (*Server, error) {
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), requestID(), accessHeaders())
	s := &Server{cfg: cfg, db: database, auth: auth.New(database.DB, cfg.SessionSecret), nodes: node.New(database.DB), subs: subscription.New(database.DB), router: r}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.router }
func (s *Server) Run() error            { return http.ListenAndServe(s.cfg.Addr, s.router) }
func (s *Server) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Server) routes() {
	s.router.GET("/", s.home)
	s.router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "subgo", "ts": time.Now().UTC().Format(time.RFC3339)})
	})
	s.router.GET("/api/version", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true, "name": "subgo", "version": Version}) })
	s.router.POST("/api/auth/login", s.login)
	s.router.POST("/api/auth/logout", s.logout)
	s.router.GET("/api/auth/me", s.me)
	s.router.GET("/sub/:token", s.subPlain)
	s.router.GET("/api/sub/:token/plain", s.subPlain)

	api := s.router.Group("/api", s.requireAuth())
	api.GET("/admin/user", s.adminUser)
	api.POST("/admin/user", s.updateAdminUser)
	api.GET("/sources", s.sources)
	api.GET("/nodes", s.listNodes)
	api.POST("/local-nodes", s.createLocalNode)
	api.POST("/nodes/:id/toggle", s.toggleNode)
	api.PUT("/nodes/:id/rename", s.renameNode)
	api.DELETE("/local-nodes/:id", s.deleteLocalNode)
	api.GET("/subscriptions", s.listSubscriptions)
	api.POST("/subscriptions", s.createSubscription)
	api.PUT("/subscriptions/:id", s.updateSubscription)
	api.DELETE("/subscriptions/:id", s.deleteSubscription)
}

func (s *Server) login(c *gin.Context) {
	var req struct{ Username, Password string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	tok, err := s.auth.Login(req.Username, req.Password)
	if err != nil {
		c.JSON(401, gin.H{"ok": false, "error": "invalid credentials"})
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "subgo_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600, Secure: isHTTPS(c)})
	c.JSON(200, gin.H{"ok": true, "username": req.Username})
}
func (s *Server) logout(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{Name: "subgo_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Secure: isHTTPS(c)})
	c.JSON(200, gin.H{"ok": true})
}
func (s *Server) me(c *gin.Context) {
	u, ok := s.currentUser(c)
	c.JSON(200, gin.H{"ok": ok, "username": u})
}
func (s *Server) adminUser(c *gin.Context) { a, err := s.auth.Admin(); jsonResult(c, a, err) }
func (s *Server) updateAdminUser(c *gin.Context) {
	var req struct{ Username, Password string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	jsonOK(c, s.auth.UpdateAdmin(req.Username, req.Password))
}
func (s *Server) sources(c *gin.Context) {
	rows, err := s.db.Query(`SELECT id,name,source_type,panel_url,enabled,last_sync_status,created_at,updated_at FROM sources ORDER BY id ASC`)
	if err != nil {
		c.JSON(500, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int64
		var name, typ, url, status, ca, ua string
		var en int
		if err := rows.Scan(&id, &name, &typ, &url, &en, &status, &ca, &ua); err != nil {
			c.JSON(500, gin.H{"ok": false, "error": err.Error()})
			return
		}
		out = append(out, gin.H{"id": id, "name": name, "source_type": typ, "panel_url": url, "enabled": en == 1, "last_sync_status": status, "created_at": ca, "updated_at": ua})
	}
	c.JSON(200, gin.H{"ok": true, "sources": out})
}
func (s *Server) listNodes(c *gin.Context) {
	v, err := s.nodes.List()
	jsonResultKey(c, "nodes", v, err)
}
func (s *Server) createLocalNode(c *gin.Context) {
	var req struct {
		RawLink string `json:"raw_link"`
		Name    string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	n, err := s.nodes.CreateLocal(req.RawLink, req.Name)
	jsonResultKey(c, "node", n, err)
}
func (s *Server) toggleNode(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct{ Enabled bool }
	_ = c.ShouldBindJSON(&req)
	jsonOK(c, s.nodes.Toggle(id, req.Enabled))
}
func (s *Server) renameNode(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct{ Name string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	jsonOK(c, s.nodes.Rename(id, req.Name))
}
func (s *Server) deleteLocalNode(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	jsonOK(c, s.nodes.DeleteLocal(id))
}
func (s *Server) listSubscriptions(c *gin.Context) {
	v, err := s.subs.List(s.publicBase(c))
	jsonResultKey(c, "subscriptions", v, err)
}
func (s *Server) createSubscription(c *gin.Context) {
	var req struct {
		Name      string  `json:"name"`
		NodeIDs   []int64 `json:"node_ids"`
		SourceIDs []int64 `json:"source_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	sub, err := s.subs.Create(req.Name, req.NodeIDs, req.SourceIDs)
	if err == nil {
		sub.PlainURL = s.publicBase(c) + "/sub/" + sub.Token
	}
	jsonResultKey(c, "subscription", sub, err)
}
func (s *Server) updateSubscription(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Name      string  `json:"name"`
		NodeIDs   []int64 `json:"node_ids"`
		SourceIDs []int64 `json:"source_ids"`
		Enabled   bool    `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	jsonOK(c, s.subs.Update(id, req.Name, req.NodeIDs, req.SourceIDs, req.Enabled))
}
func (s *Server) deleteSubscription(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	jsonOK(c, s.subs.Delete(id))
}
func (s *Server) subPlain(c *gin.Context) {
	out, err := s.subs.PlainLinks(c.Param("token"), c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		status := 404
		if err.Error() == "subscription disabled" {
			status = 403
		}
		c.String(status, err.Error())
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(200, out)
}

func (s *Server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := s.currentUser(c); !ok {
			c.JSON(401, gin.H{"ok": false, "error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}
func (s *Server) currentUser(c *gin.Context) (string, bool) {
	ck, err := c.Cookie("subgo_session")
	if err != nil {
		return "", false
	}
	return s.auth.Verify(ck)
}
func (s *Server) publicBase(c *gin.Context) string {
	if s.cfg.BaseURL != "" {
		return s.cfg.BaseURL
	}
	scheme := c.GetHeader("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host
}

func jsonOK(c *gin.Context, err error) {
	if err != nil {
		c.JSON(errStatus(err), gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func jsonResult(c *gin.Context, v any, err error) {
	if err != nil {
		c.JSON(errStatus(err), gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true, "data": v})
}
func jsonResultKey(c *gin.Context, key string, v any, err error) {
	if err != nil {
		c.JSON(errStatus(err), gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true, key: v})
}
func errStatus(err error) int {
	if errors.Is(err, sql.ErrNoRows) {
		return 404
	}
	return 400
}
func isHTTPS(c *gin.Context) bool {
	return c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
}

func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Request-Id") == "" {
			c.Header("X-Request-Id", time.Now().UTC().Format("20060102150405.000000000"))
		}
		c.Next()
	}
}
func accessHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

func (s *Server) home(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>subgo — Go 重构版 Sub</title><style>body{margin:0;font-family:ui-sans-serif,system-ui;background:#07111f;color:#eef6ff}main{max-width:1080px;margin:auto;padding:56px 20px}.card{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);border-radius:28px;padding:32px;margin:18px 0}h1{font-size:78px;letter-spacing:-.07em;margin:0 0 16px}.btn{display:inline-block;padding:12px 16px;border-radius:12px;background:#00add8;color:#06111f;text-decoration:none;font-weight:800;margin:8px 8px 0 0}.muted{color:#96a8bd;line-height:1.7}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.item{background:rgba(255,255,255,.06);border-radius:18px;padding:18px}</style></head><body><main><div class="card"><b>subgo.zzao.de · Go Rewrite Preview</b><h1>subgo</h1><p class="muted">Sub / sui-sub 的 Go 语言全面重构版。当前已进入最小可用闭环：新 SQLite schema、登录/session、本地节点录入、订阅 plain 输出。</p><a class="btn" href="https://github.com/Spittingjiu/subgo">GitHub</a><a class="btn" href="/api/version">版本 API</a><a class="btn" href="/healthz">健康检查</a></div><div class="card"><h2>本轮已补能力</h2><div class="grid"><div class="item">SQLite schema + repository 基础</div><div class="item">管理登录/session API</div><div class="item">本地节点录入/列表/重命名/开关/删除</div><div class="item">订阅创建/列表/plain 链接输出</div></div></div><p class="muted">version `+Version+` · Go 单二进制 · systemd</p></main></body></html>`)
}
