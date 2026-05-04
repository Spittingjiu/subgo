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
	s.router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "service": "subgo", "ts": time.Now().UTC().Format(time.RFC3339)})
	})
	s.router.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "name": "subgo", "version": Version})
	})
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
