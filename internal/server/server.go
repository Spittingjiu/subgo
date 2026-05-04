package server

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/config"
	"github.com/Spittingjiu/subgo/internal/db"
	"github.com/Spittingjiu/subgo/internal/services/auth"
	"github.com/Spittingjiu/subgo/internal/services/connectivity"
	"github.com/Spittingjiu/subgo/internal/services/node"
	"github.com/Spittingjiu/subgo/internal/services/source"
	"github.com/Spittingjiu/subgo/internal/services/subscription"
	"github.com/gin-gonic/gin"
)

const Version = "0.3.0-dev"

type Server struct {
	cfg       config.Config
	db        *db.DB
	auth      *auth.Service
	nodes     *node.Service
	subs      *subscription.Service
	sourceSvc *source.Service
	conn      *connectivity.Service
	router    *gin.Engine
}

func New(cfg config.Config) (*Server, error) {
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), requestID(), accessHeaders())
	s := &Server{cfg: cfg, db: database, auth: auth.New(database.DB, cfg.SessionSecret), nodes: node.New(database.DB), subs: subscription.New(database.DB), sourceSvc: source.New(database.DB), conn: connectivity.New(database.DB), router: r}
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
	s.router.GET("/", s.app)
	s.router.GET("/app", s.app)
	s.router.GET("/about", s.home)
	s.router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "subgo", "ts": time.Now().UTC().Format(time.RFC3339)})
	})
	s.router.GET("/api/version", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true, "name": "subgo", "version": Version}) })
	s.router.POST("/api/auth/login", s.login)
	s.router.POST("/api/auth/logout", s.logout)
	s.router.GET("/api/auth/me", s.me)
	s.router.GET("/sub/:token", s.subPlain)
	s.router.GET("/api/sub/:token/plain", s.subPlain)
	s.router.Any("/panel-proxy/:sourceId/*path", s.panelProxy)
	s.router.GET("/sub/:token/clash", s.subClash)
	s.router.GET("/api/sub/:token/clash", s.subClash)

	api := s.router.Group("/api", s.requireAuth())
	api.GET("/admin/user", s.adminUser)
	api.POST("/admin/user", s.updateAdminUser)
	api.GET("/sources", s.sources)
	api.POST("/sources", s.createSource)
	api.PUT("/sources/:id", s.updateSource)
	api.DELETE("/sources/:id", s.deleteSource)
	api.POST("/sources/:id/sync", s.syncSource)
	api.POST("/sources/sync-all", s.syncAllSources)
	api.GET("/kernel/status", s.kernelStatus)
	api.GET("/nodes/connectivity", s.connectivityList)
	api.POST("/nodes/connectivity/check", s.connectivityCheck)
	api.POST("/admin/connectivity/run-now", s.connectivityCheck)
	api.GET("/admin/subscription-logs", s.subscriptionLogs)
	api.GET("/view/home", s.viewHome)
	api.GET("/view/nodes", s.listNodes)
	api.GET("/view/bootstrap", s.viewBootstrap)
	api.GET("/view/modal-nodes", s.listNodes)
	api.GET("/view/subscriptions", s.listSubscriptions)
	api.GET("/sui/:sourceId/inbounds", s.suiInbounds)
	api.POST("/sui/:sourceId/reality-quick", s.suiRealityQuick)
	api.PUT("/sui/:sourceId/inbounds/:inboundId/rename", s.suiInboundRename)
	api.DELETE("/sui/:sourceId/inbounds/:inboundId", s.suiInboundDelete)
	api.POST("/kernel/install", s.kernelInstall)
	api.POST("/kernel/uninstall", s.kernelUninstall)
	api.GET("/bridge/e2ee-meta", s.bridgeMeta)
	api.POST("/bridge/push-source", s.bridgePushSource)
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
	v, err := s.sourceSvc.List()
	jsonResultKey(c, "sources", v, err)
}
func (s *Server) createSource(c *gin.Context) {
	var req struct {
		Name       string `json:"name"`
		SourceType string `json:"source_type"`
		PanelURL   string `json:"panel_url"`
		PanelToken string `json:"panel_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	v, err := s.sourceSvc.Create(req.Name, req.SourceType, req.PanelURL, req.PanelToken)
	jsonResultKey(c, "source", v, err)
}
func (s *Server) updateSource(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Name       string `json:"name"`
		PanelURL   string `json:"panel_url"`
		PanelToken string `json:"panel_token"`
		Enabled    bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"ok": false, "error": "bad json"})
		return
	}
	jsonOK(c, s.sourceSvc.Update(id, req.Name, req.PanelURL, req.PanelToken, req.Enabled))
}
func (s *Server) deleteSource(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	jsonOK(c, s.sourceSvc.Delete(id))
}
func (s *Server) syncSource(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	jsonOK(c, s.sourceSvc.Sync(id))
}
func (s *Server) syncAllSources(c *gin.Context) {
	c.JSON(200, gin.H{"ok": true, "results": s.sourceSvc.SyncAll()})
}
func (s *Server) kernelStatus(c *gin.Context) { c.JSON(200, s.conn.KernelStatus()) }
func (s *Server) connectivityList(c *gin.Context) {
	v, err := s.conn.List()
	jsonResultKey(c, "connectivity", v, err)
}
func (s *Server) connectivityCheck(c *gin.Context) {
	limit, _ := strconv.Atoi(c.Query("limit"))
	v, err := s.conn.Check(limit)
	jsonResultKey(c, "results", v, err)
}
func (s *Server) subscriptionLogs(c *gin.Context) {
	rows, err := s.db.Query(`SELECT id,token,subscription_id,subscription_name,route_type,client_ip,user_agent,created_at FROM subscription_logs ORDER BY id DESC LIMIT 200`)
	if err != nil {
		c.JSON(500, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id, sid int64
		var token, name, rt, ip, ua, ca string
		_ = rows.Scan(&id, &token, &sid, &name, &rt, &ip, &ua, &ca)
		out = append(out, gin.H{"id": id, "token": token, "subscription_id": sid, "subscription_name": name, "route_type": rt, "client_ip": ip, "user_agent": ua, "created_at": ca})
	}
	c.JSON(200, gin.H{"ok": true, "logs": out})
}

func (s *Server) viewHome(c *gin.Context) {
	sources, _ := s.sourceSvc.List()
	nodes, _ := s.nodes.List()
	subs, _ := s.subs.List(s.publicBase(c))
	c.JSON(200, gin.H{"ok": true, "stats": gin.H{"sources": len(sources), "nodes": len(nodes), "subscriptions": len(subs)}})
}
func (s *Server) viewBootstrap(c *gin.Context) {
	sources, _ := s.sourceSvc.List()
	nodes, _ := s.nodes.List()
	subs, _ := s.subs.List(s.publicBase(c))
	c.JSON(200, gin.H{"ok": true, "sources": sources, "nodes": nodes, "subscriptions": subs})
}
func (s *Server) suiInbounds(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("sourceId"), 10, 64)
	v, err := s.sourceSvc.Inbounds(id)
	jsonResultKey(c, "inbounds", v, err)
}
func (s *Server) suiRealityQuick(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("sourceId"), 10, 64)
	var req struct {
		Remark string `json:"remark"`
	}
	_ = c.ShouldBindJSON(&req)
	v, err := s.sourceSvc.RealityQuick(id, req.Remark)
	if err == nil {
		_ = s.sourceSvc.Sync(id)
	}
	jsonResultKey(c, "obj", v, err)
}
func (s *Server) suiInboundRename(c *gin.Context) {
	sid, _ := strconv.ParseInt(c.Param("sourceId"), 10, 64)
	iid, _ := strconv.ParseInt(c.Param("inboundId"), 10, 64)
	var req struct {
		Remark string `json:"remark"`
	}
	_ = c.ShouldBindJSON(&req)
	err := s.sourceSvc.RenameInbound(sid, iid, req.Remark)
	if err == nil {
		_ = s.sourceSvc.Sync(sid)
	}
	jsonOK(c, err)
}
func (s *Server) suiInboundDelete(c *gin.Context) {
	sid, _ := strconv.ParseInt(c.Param("sourceId"), 10, 64)
	iid, _ := strconv.ParseInt(c.Param("inboundId"), 10, 64)
	err := s.sourceSvc.DeleteInbound(sid, iid)
	if err == nil {
		_ = s.sourceSvc.Sync(sid)
	}
	jsonOK(c, err)
}
func (s *Server) kernelInstall(c *gin.Context) {
	v, err := s.conn.InstallMihomo()
	if err != nil {
		c.JSON(500, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true, "version": v})
}
func (s *Server) kernelUninstall(c *gin.Context) { jsonOK(c, s.conn.UninstallMihomo()) }
func (s *Server) bridgeMeta(c *gin.Context) {
	c.JSON(200, gin.H{"ok": true, "enabled": false, "message": "bridge E2EE push is pending"})
}
func (s *Server) bridgePushSource(c *gin.Context) {
	c.JSON(501, gin.H{"ok": false, "error": "bridge push-source is pending"})
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

func (s *Server) panelProxy(c *gin.Context) {
	if _, ok := s.currentUser(c); !ok {
		c.String(401, "unauthorized")
		return
	}
	sid, _ := strconv.ParseInt(c.Param("sourceId"), 10, 64)
	src, err := s.sourceSvc.Get(sid)
	if err != nil {
		c.String(404, "source not found")
		return
	}
	if src.Type == "local" {
		c.String(400, "local source not supported")
		return
	}
	base := strings.TrimRight(src.PanelURL, "/")
	if strings.Contains(base, "/api/v1/sub/") {
		if u, er := url.Parse(base); er == nil {
			base = u.Scheme + "://" + u.Host
		}
	}
	tail := c.Param("path")
	target := base + tail
	if c.Request.URL.RawQuery != "" {
		target += "?" + c.Request.URL.RawQuery
	}
	if err := source.AssertURLSafe(target); err != nil {
		c.String(403, err.Error())
		return
	}
	method := c.Request.Method
	if method == "TRACE" || method == "CONNECT" {
		c.String(405, "method not allowed")
		return
	}
	var body io.Reader
	if method != "GET" && method != "HEAD" {
		body = c.Request.Body
	}
	req, _ := http.NewRequest(method, target, body)
	for _, h := range []string{"Accept", "Accept-Language", "Content-Type", "User-Agent"} {
		if v := c.GetHeader(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if ck := filterProxyCookie(c.GetHeader("Cookie")); ck != "" {
		req.Header.Set("Cookie", ck)
	}
	if src.PanelToken != "" {
		req.Header.Set("X-Panel-Token", src.PanelToken)
		req.Header.Set("Authorization", "Bearer "+src.PanelToken)
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		c.String(502, "panel proxy error: "+err.Error())
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "set-cookie" {
			continue
		}
		for _, v := range vals {
			c.Writer.Header().Add(k, v)
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, er := url.Parse(loc); er == nil {
			if !u.IsAbs() {
				loc = "/panel-proxy/" + strconv.FormatInt(sid, 10) + loc
			}
		}
		c.Header("Location", loc)
	}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		c.Writer.Header().Add("Set-Cookie", rewriteProxySetCookie(sc, sid))
	}
	c.Status(resp.StatusCode)
	_, _ = io.Copy(c.Writer, io.LimitReader(resp.Body, 16<<20))
}
func filterProxyCookie(raw string) string {
	parts := strings.Split(raw, ";")
	keep := []string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "subgo_session=") {
			continue
		}
		keep = append(keep, p)
	}
	return strings.Join(keep, "; ")
}
func rewriteProxySetCookie(raw string, sid int64) string {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return raw
	}
	out := []string{parts[0], "Path=/panel-proxy/" + strconv.FormatInt(sid, 10), "HttpOnly", "SameSite=Lax"}
	return strings.Join(out, "; ")
}

func (s *Server) subClash(c *gin.Context) {
	out, err := s.subs.Clash(c.Param("token"), c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		c.String(404, err.Error())
		return
	}
	c.Header("Content-Type", "text/yaml; charset=utf-8")
	c.String(200, out)
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

func (s *Server) app(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>subgo 管理台</title><style>
:root{--bg:#07111f;--card:#101d31;--card2:#0d1829;--line:rgba(255,255,255,.12);--text:#eef6ff;--muted:#9fb0c6;--go:#00add8;--ok:#7cffc7;--bad:#ff7d7d}*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,"PingFang SC",sans-serif;background:radial-gradient(circle at 20% 0%,rgba(0,173,216,.22),transparent 34%),var(--bg);color:var(--text)}.wrap{max-width:1240px;margin:auto;padding:22px}.top{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:16px}.brand h1{margin:0;font-size:42px;letter-spacing:-.05em}.brand p{margin:4px 0 0;color:var(--muted)}.card{background:rgba(16,29,49,.92);border:1px solid var(--line);border-radius:20px;padding:18px;margin:14px 0;box-shadow:0 18px 50px rgba(0,0,0,.22)}input,select,button,textarea{font-size:16px;border-radius:12px;border:1px solid rgba(255,255,255,.16);padding:11px;background:#0b1626;color:var(--text)}button{background:var(--go);color:#06111f;font-weight:800;cursor:pointer;border:0}button.ghost{background:#1b2a42;color:var(--text)}button.danger{background:#ff7d7d}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.muted{color:var(--muted);line-height:1.6}.item{border-top:1px solid var(--line);padding:12px 0;word-break:break-all}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#18304d;color:#bdefff;font-size:12px}.stat{font-size:28px;font-weight:900;color:var(--ok)}a{color:#7cffc7}.hidden{display:none!important}.full{grid-column:1/-1}textarea{width:100%;min-height:92px}.toast{position:fixed;right:18px;bottom:18px;background:#10243d;border:1px solid var(--line);padding:12px 14px;border-radius:12px;max-width:360px}.tabs button{margin-right:8px;margin-bottom:8px}@media(max-width:900px){.grid{grid-template-columns:1fr}.top{display:block}.brand h1{font-size:34px}}
</style></head><body><div class="wrap"><div class="top"><div class="brand"><h1>subgo 管理台</h1><p>打开网页就能管理源、节点和订阅；默认账号 admin / admin123</p></div><div class="row"><a href="/about">项目说明</a><button id="logoutBtn" class="ghost hidden" onclick="doLogout()">退出登录</button></div></div>
<div id="loginBox" class="card"><h2>登录</h2><p class="muted">登录后可以添加订阅源、手动添加节点、生成 plain / Clash 订阅链接。</p><div class="row"><input id="u" value="admin" placeholder="用户名"><input id="p" value="admin123" type="password" placeholder="密码"><button onclick="doLogin()">登录进入管理台</button></div></div>
<div id="mainApp" class="hidden"><div class="grid"><div class="card"><div class="muted">源数量</div><div id="statSources" class="stat">0</div></div><div class="card"><div class="muted">节点数量</div><div id="statNodes" class="stat">0</div></div><div class="card"><div class="muted">订阅数量</div><div id="statSubs" class="stat">0</div></div></div>
<div class="card"><div class="tabs"><button onclick="loadAll()">刷新</button><button onclick="syncAll()">同步全部源</button><button onclick="checkConn()">检测连通性</button></div><span class="muted">常用流程：添加源或本地节点 → 创建订阅 → 复制 plain/Clash 链接到客户端。</span></div>
<div class="grid"><div class="card"><h2>1. 添加源</h2><p class="muted">粘贴机场/面板订阅地址。SBUI 填面板地址即可。</p><input id="sn" placeholder="源名称，例如 AU 机器"><select id="st"><option value="cf_sub">普通订阅/raw</option><option value="sbui">SBUI / S-Matrix</option><option value="sui_api">SUI API/订阅</option></select><input id="su" placeholder="订阅或面板 URL"><input id="sk" placeholder="Token 可选"><button onclick="addSource()">添加源</button><div id="sources"></div></div>
<div class="card"><h2>2. 本地节点</h2><p class="muted">临时手动录入单个 vless / hy2 / ss / trojan 链接。</p><textarea id="raw" placeholder="vless://...#节点名"></textarea><input id="nn" placeholder="节点名可选"><button onclick="addNode()">添加本地节点</button><div id="nodes"></div></div>
<div class="card"><h2>3. 创建订阅</h2><p class="muted">节点 ID 留空表示输出全部可用节点。</p><input id="subname" placeholder="订阅名，例如 iPhone"><input id="nodeids" placeholder="节点ID，逗号分隔，空=全部"><button onclick="addSub()">创建订阅</button><div id="subs"></div></div>
<div class="card full"><h2>状态与检测结果</h2><pre id="status" class="muted">等待操作...</pre></div></div></div></div><div id="toast" class="toast hidden"></div><script>
const $=id=>document.getElementById(id);function show(msg){$('toast').textContent=msg;$('toast').classList.remove('hidden');setTimeout(()=>$('toast').classList.add('hidden'),2600)}
async function api(path,opt={}){opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});let r=await fetch(path,opt);let t=await r.text();let j;try{j=JSON.parse(t)}catch(e){j={ok:r.ok,text:t}};if(!r.ok&&j.error)throw new Error(j.error);return j}
function authed(on){$('loginBox').classList.toggle('hidden',on);$('mainApp').classList.toggle('hidden',!on);$('logoutBtn').classList.toggle('hidden',!on)}
async function doLogin(){try{let j=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:$('u').value,password:$('p').value})}); if(j.ok){authed(true);show('登录成功');loadAll()}}catch(e){show('登录失败：'+e.message)}}
async function doLogout(){await api('/api/auth/logout',{method:'POST'});authed(false)}
async function loadAll(){try{let me=await api('/api/auth/me'); if(!me.ok){authed(false);return} authed(true); let so=await api('/api/sources'), no=await api('/api/nodes'), sub=await api('/api/subscriptions'), co=await api('/api/nodes/connectivity'); let sources=so.sources||[], nodes=no.nodes||[], subs=sub.subscriptions||[]; $('statSources').textContent=sources.length;$('statNodes').textContent=nodes.length;$('statSubs').textContent=subs.length; $('sources').innerHTML=sources.map(x=>'<div class=item><b>#'+x.id+' '+esc(x.name)+'</b> <span class=pill>'+esc(x.source_type)+'</span> <span class=pill>'+esc(x.last_sync_status||'')+'</span><br><span class=muted>'+esc(x.panel_url||'系统本地源')+'</span><br><button onclick="sync('+x.id+')">同步</button> '+(x.source_type==='local'?'':'<button class=danger onclick="delSource('+x.id+')">删除</button>')+'</div>').join(''); $('nodes').innerHTML=nodes.map(x=>'<div class=item><b>#'+x.id+' '+esc(x.display_no)+' '+esc(x.node_name)+'</b> <span class=pill>'+esc(x.protocol)+'</span> <span class=pill>'+(x.enabled?'启用':'禁用')+'</span><br><span class=muted>'+esc(x.raw_link)+'</span><br><button onclick="toggleNode('+x.id+','+(!x.enabled)+')">'+(x.enabled?'禁用':'启用')+'</button> <button class=ghost onclick="renNode('+x.id+')">改名</button> <button class=danger onclick="delNode('+x.id+')">删除本地</button></div>').join(''); $('subs').innerHTML=subs.map(x=>'<div class=item><b>#'+x.id+' '+esc(x.name)+'</b><br><a target=_blank href="'+x.plain_url+'">Plain 订阅</a> · <a target=_blank href="/sub/'+x.token+'/clash">Clash 订阅</a><br><button onclick="copy(\''+x.plain_url+'\')">复制 Plain</button> <button onclick="copy(location.origin+\'/sub/'+x.token+'/clash\')">复制 Clash</button></div>').join(''); $('status').textContent=JSON.stringify(co,null,2)}catch(e){show(e.message)}}
function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function addSource(){try{await api('/api/sources',{method:'POST',body:JSON.stringify({name:$('sn').value,source_type:$('st').value,panel_url:$('su').value,panel_token:$('sk').value})});show('源已添加');loadAll()}catch(e){show(e.message)}}
async function sync(id){try{await api('/api/sources/'+id+'/sync',{method:'POST'});show('同步完成');loadAll()}catch(e){show('同步失败：'+e.message);loadAll()}}
async function syncAll(){try{$('status').textContent=JSON.stringify(await api('/api/sources/sync-all',{method:'POST'}),null,2);loadAll()}catch(e){show(e.message)}}
async function delSource(id){if(confirm('删除这个源？')){await api('/api/sources/'+id,{method:'DELETE'});loadAll()}}
async function addNode(){try{await api('/api/local-nodes',{method:'POST',body:JSON.stringify({raw_link:$('raw').value,name:$('nn').value})});show('节点已添加');loadAll()}catch(e){show(e.message)}}
async function toggleNode(id,en){await api('/api/nodes/'+id+'/toggle',{method:'POST',body:JSON.stringify({enabled:en})});loadAll()}
async function renNode(id){let name=prompt('新名称'); if(name){await api('/api/nodes/'+id+'/rename',{method:'PUT',body:JSON.stringify({name})});loadAll()}}
async function delNode(id){if(confirm('删除这个本地节点？')){await api('/api/local-nodes/'+id,{method:'DELETE'});loadAll()}}
async function addSub(){try{let ids=$('nodeids').value.split(',').map(x=>parseInt(x.trim())).filter(Boolean);await api('/api/subscriptions',{method:'POST',body:JSON.stringify({name:$('subname').value,node_ids:ids})});show('订阅已创建');loadAll()}catch(e){show(e.message)}}
async function checkConn(){try{$('status').textContent=JSON.stringify(await api('/api/nodes/connectivity/check?limit=100',{method:'POST'}),null,2);loadAll()}catch(e){show(e.message)}}
async function copy(t){await navigator.clipboard.writeText(t);show('已复制')}
loadAll();
</script></body></html>`)
}
