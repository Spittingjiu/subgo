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
	"github.com/Spittingjiu/subgo/internal/services/connectivity"
	"github.com/Spittingjiu/subgo/internal/services/node"
	"github.com/Spittingjiu/subgo/internal/services/source"
	"github.com/Spittingjiu/subgo/internal/services/subscription"
	"github.com/gin-gonic/gin"
)

const Version = "0.2.0-dev"

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
	s.router.GET("/", s.home)
	s.router.GET("/app", s.app)
	s.router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "subgo", "ts": time.Now().UTC().Format(time.RFC3339)})
	})
	s.router.GET("/api/version", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true, "name": "subgo", "version": Version}) })
	s.router.POST("/api/auth/login", s.login)
	s.router.POST("/api/auth/logout", s.logout)
	s.router.GET("/api/auth/me", s.me)
	s.router.GET("/sub/:token", s.subPlain)
	s.router.GET("/api/sub/:token/plain", s.subPlain)
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
func (s *Server) kernelStatus(c *gin.Context) {
	c.JSON(200, gin.H{"ok": true, "installed": false, "mode": "tcp-check", "message": "subgo uses built-in TCP connectivity checks; mihomo install comes later"})
}
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
	c.String(http.StatusOK, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>subgo 管理台</title><style>body{margin:0;font-family:system-ui,-apple-system,"PingFang SC",sans-serif;background:#07111f;color:#eef6ff}.wrap{max-width:1180px;margin:auto;padding:22px}.card{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);border-radius:18px;padding:18px;margin:14px 0}input,select,button,textarea{font-size:16px;border-radius:10px;border:1px solid rgba(255,255,255,.18);padding:10px;background:#0d1b2d;color:#eef6ff}button{background:#00add8;color:#06111f;font-weight:800;cursor:pointer}.row{display:flex;gap:8px;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.muted{color:#9fb0c6}.item{border-top:1px solid rgba(255,255,255,.12);padding:10px 0;word-break:break-all}a{color:#7cffc7}</style></head><body><div class="wrap"><h1>subgo 管理台</h1><div id="login" class="card"><h2>登录</h2><div class="row"><input id="u" value="admin" placeholder="用户名"><input id="p" value="admin123" type="password" placeholder="密码"><button onclick="login()">登录</button></div></div><div id="app" style="display:none"><div class="card"><div class="row"><button onclick="loadAll()">刷新</button><button onclick="syncAll()">同步全部源</button><button onclick="checkConn()">连通性检测</button><button onclick="logout()">退出</button></div><p class="muted">plain: /sub/:token · clash: /sub/:token/clash</p></div><div class="grid"><div class="card"><h2>添加源</h2><input id="sn" placeholder="名称"><select id="st"><option value="cf_sub">raw/cf_sub</option><option value="sbui">SBUI</option><option value="sui_api">SUI API</option></select><input id="su" placeholder="订阅或面板 URL"><input id="sk" placeholder="Token 可选"><button onclick="addSource()">添加源</button><div id="sources"></div></div><div class="card"><h2>本地节点</h2><textarea id="raw" rows="4" style="width:100%" placeholder="vless://...#name"></textarea><input id="nn" placeholder="节点名可选"><button onclick="addNode()">添加本地节点</button><div id="nodes"></div></div><div class="card"><h2>订阅</h2><input id="subname" placeholder="订阅名"><input id="nodeids" placeholder="节点ID，逗号分隔，空=全部"><button onclick="addSub()">创建订阅</button><div id="subs"></div></div></div><div class="card"><h2>连通性/日志</h2><pre id="status" class="muted"></pre></div></div></div><script>
async function api(path,opt={}){opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});let r=await fetch(path,opt);let t=await r.text();try{return JSON.parse(t)}catch(e){return {ok:r.ok,text:t}}}
async function login(){let j=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:u.value,password:p.value})}); if(j.ok){login.style.display='none';app.style.display='block';loadAll()}else alert(j.error||'fail')}
async function logout(){await api('/api/auth/logout',{method:'POST'}); location.reload()}
async function loadAll(){let me=await api('/api/auth/me'); if(me.ok){login.style.display='none';app.style.display='block'}; let so=await api('/api/sources'), no=await api('/api/nodes'), sub=await api('/api/subscriptions'), co=await api('/api/nodes/connectivity'); sources.innerHTML=(so.sources||[]).map(x=>' <div class=item><b>#'+x.id+' '+x.name+'</b> '+x.source_type+' '+x.last_sync_status+'<br>'+(x.panel_url||'')+'<br><button onclick="sync('+x.id+')">同步</button> <button onclick="delSource('+x.id+')">删除</button></div>').join(''); nodes.innerHTML=(no.nodes||[]).map(x=>' <div class=item><b>#'+x.id+' '+x.display_no+' '+x.node_name+'</b> '+x.protocol+' '+(x.enabled?'启用':'禁用')+'<br>'+x.raw_link+'<br><button onclick="toggleNode('+x.id+','+(!x.enabled)+')">'+(x.enabled?'禁用':'启用')+'</button> <button onclick="renNode('+x.id+')">改名</button> <button onclick="delNode('+x.id+')">删除本地</button></div>').join(''); subs.innerHTML=(sub.subscriptions||[]).map(x=>' <div class=item><b>#'+x.id+' '+x.name+'</b><br><a href="'+x.plain_url+'">'+x.plain_url+'</a><br><a href="/sub/'+x.token+'/clash">/sub/'+x.token+'/clash</a></div>').join(''); status.textContent=JSON.stringify(co,null,2)}
async function addSource(){await api('/api/sources',{method:'POST',body:JSON.stringify({name:sn.value,source_type:st.value,panel_url:su.value,panel_token:sk.value})});loadAll()}
async function sync(id){let j=await api('/api/sources/'+id+'/sync',{method:'POST'}); if(!j.ok) alert(j.error); loadAll()}
async function syncAll(){status.textContent=JSON.stringify(await api('/api/sources/sync-all',{method:'POST'}),null,2);loadAll()}
async function delSource(id){if(confirm('删除源?')){await api('/api/sources/'+id,{method:'DELETE'});loadAll()}}
async function addNode(){await api('/api/local-nodes',{method:'POST',body:JSON.stringify({raw_link:raw.value,name:nn.value})});loadAll()}
async function toggleNode(id,en){await api('/api/nodes/'+id+'/toggle',{method:'POST',body:JSON.stringify({enabled:en})});loadAll()}
async function renNode(id){let name=prompt('新名称'); if(name) await api('/api/nodes/'+id+'/rename',{method:'PUT',body:JSON.stringify({name})});loadAll()}
async function delNode(id){if(confirm('删除本地节点?')){await api('/api/local-nodes/'+id,{method:'DELETE'});loadAll()}}
async function addSub(){let ids=nodeids.value.split(',').map(x=>parseInt(x.trim())).filter(Boolean);await api('/api/subscriptions',{method:'POST',body:JSON.stringify({name:subname.value,node_ids:ids})});loadAll()}
async function checkConn(){status.textContent=JSON.stringify(await api('/api/nodes/connectivity/check?limit=100',{method:'POST'}),null,2);loadAll()}
loadAll();
</script></body></html>`)
}
