package server

import (
	"net/http"
	"time"

	"github.com/Spittingjiu/subgo/internal/config"
	"github.com/gin-gonic/gin"
)

const Version = "0.1.0-dev"

type Server struct {
	cfg    config.Config
	router *gin.Engine
}

func New(cfg config.Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), requestID(), accessHeaders())

	s := &Server{cfg: cfg, router: r}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) Run() error { return http.ListenAndServe(s.cfg.Addr, s.router) }

func (s *Server) routes() {
	s.router.GET("/", s.home)
	s.router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "subgo", "ts": time.Now().UTC().Format(time.RFC3339)})
	})
	s.router.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "name": "subgo", "version": Version})
	})
}

func (s *Server) home(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>subgo — Go 重构版 Sub</title>
  <style>
    :root{color-scheme:dark;--bg:#07111f;--card:rgba(255,255,255,.075);--line:rgba(255,255,255,.14);--text:#eef6ff;--muted:#96a8bd;--go:#00add8;--ok:#7cffc7;--warn:#ffd166}
    *{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;background:radial-gradient(circle at 20% 0%,rgba(0,173,216,.30),transparent 38%),radial-gradient(circle at 90% 20%,rgba(124,255,199,.18),transparent 34%),var(--bg);color:var(--text)}
    main{max-width:1120px;margin:0 auto;padding:56px 20px 72px}.hero{display:grid;grid-template-columns:1.25fr .75fr;gap:24px;align-items:stretch}.card{background:var(--card);border:1px solid var(--line);border-radius:28px;box-shadow:0 22px 70px rgba(0,0,0,.28);backdrop-filter:blur(14px)}.intro{padding:42px}.badge{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border-radius:999px;background:rgba(0,173,216,.14);border:1px solid rgba(0,173,216,.35);color:#bdf5ff;font-weight:700;font-size:13px}h1{font-size:clamp(44px,8vw,88px);line-height:.92;margin:24px 0 18px;letter-spacing:-.07em}.lead{font-size:20px;line-height:1.7;color:#c9d7e6;margin:0;max-width:760px}.actions{display:flex;gap:14px;flex-wrap:wrap;margin-top:28px}.btn{display:inline-flex;text-decoration:none;color:#06111f;background:var(--go);font-weight:800;padding:13px 18px;border-radius:14px}.btn.ghost{color:var(--text);background:rgba(255,255,255,.08);border:1px solid var(--line)}.panel{padding:28px}.go-logo{font-size:96px;font-weight:900;letter-spacing:-.12em;color:var(--go);margin-bottom:20px}.metric{display:flex;justify-content:space-between;gap:16px;padding:15px 0;border-top:1px solid var(--line)}.metric b{color:var(--ok)}.section{margin-top:24px;padding:28px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.item{padding:20px;border-radius:20px;background:rgba(255,255,255,.055);border:1px solid var(--line)}.item h3{margin:0 0 10px;font-size:18px}.item p{margin:0;color:var(--muted);line-height:1.55}.road{display:grid;grid-template-columns:repeat(6,1fr);gap:10px}.step{padding:14px;border-radius:16px;background:rgba(0,173,216,.09);border:1px solid rgba(0,173,216,.22);font-size:13px;color:#cdeffa}.step b{display:block;color:white;margin-bottom:6px}.foot{margin-top:28px;color:var(--muted);font-size:13px;text-align:center}@media(max-width:840px){.hero{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.road{grid-template-columns:1fr 1fr}.intro{padding:28px}}
  </style>
</head>
<body>
<main>
  <section class="hero">
    <div class="card intro">
      <span class="badge">subgo.zzao.de · Go Rewrite Preview</span>
      <h1>subgo</h1>
      <p class="lead">Sub / sui-sub 的 Go 语言全面重构版。目标不是换个语言，而是利用 Go 的并发、单二进制部署、强类型边界和高吞吐网络能力，把多源订阅编排做得更快、更稳、更容易长期维护。</p>
      <div class="actions"><a class="btn" href="https://github.com/Spittingjiu/subgo">GitHub 仓库</a><a class="btn ghost" href="/api/version">版本 API</a><a class="btn ghost" href="/healthz">健康检查</a></div>
    </div>
    <div class="card panel">
      <div class="go-logo">GO</div>
      <div class="metric"><span>当前阶段</span><b>Phase 0 骨架已上线</b></div>
      <div class="metric"><span>运行形态</span><b>Go 单二进制 + systemd</b></div>
      <div class="metric"><span>默认监听</span><b>127.0.0.1:8781</b></div>
      <div class="metric"><span>重构策略</span><b>旁路兼容，验证后切换</b></div>
    </div>
  </section>

  <section class="card section">
    <h2>Go 优势会怎么用</h2>
    <div class="grid">
      <div class="item"><h3>并发同步</h3><p>用 goroutine + context + worker pool 处理多源同步、节点检测和超时取消，避免旧版串行/阻塞拖慢全局。</p></div>
      <div class="item"><h3>强类型解析</h3><p>把 VLESS/HY2/SS/Trojan、Reality、xhttp 等参数解析成明确结构体，减少字符串拼接误伤。</p></div>
      <div class="item"><h3>单二进制部署</h3><p>后端、静态资源、迁移逻辑逐步收敛成一个可审计产物，systemd 灰度发布和回滚更干净。</p></div>
      <div class="item"><h3>流式订阅输出</h3><p>订阅生成走低内存流式输出和缓存，面对大量节点/多客户端访问更稳。</p></div>
      <div class="item"><h3>安全默认值</h3><p>SSRF 防线、私网地址阻断、代理 Cookie 改写、token 隔离会作为底层中间件实现。</p></div>
      <div class="item"><h3>可测试核心</h3><p>订阅转换、节点过滤、连通性判定和迁移脚本都拆成可单测模块，避免线上靠感觉改。</p></div>
    </div>
  </section>

  <section class="card section">
    <h2>重构路线</h2>
    <div class="road">
      <div class="step"><b>0 骨架</b>仓库、服务、展示页</div>
      <div class="step"><b>1 数据层</b>兼容旧 SQLite schema</div>
      <div class="step"><b>2 订阅核心</b>plain / mihomo 输出</div>
      <div class="step"><b>3 源同步</b>SUI/SBUI/raw/local</div>
      <div class="step"><b>4 管理台</b>API + 前端迁移</div>
      <div class="step"><b>5 灰度</b>diff 验证后切正式</div>
    </div>
  </section>
  <div class="foot">subgo preview · built with Go · version `+Version+`</div>
</main>
</body>
</html>`)
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
