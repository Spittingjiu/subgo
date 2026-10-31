package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// Serve public static assets (CSS, JS, fonts, images) from the web directory.
func (s *Server) registerWebAssets() {
	roots := []string{
		filepath.Join("web"),
		filepath.Join("src", "web"),
		"/opt/subgo/src/web",
	}

	assetHandler := func(c *gin.Context) {
		reqPath := strings.TrimPrefix(c.Request.URL.Path, "/assets/")
		reqPath = filepath.Clean(reqPath)
		if strings.HasPrefix(reqPath, "..") || strings.Contains(reqPath, string(filepath.Separator)+"..") {
			c.Status(http.StatusForbidden)
			return
		}

		for _, root := range roots {
			// Check root/assets/<reqPath>
			p := filepath.Join(root, "assets", reqPath)
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				c.Header("Cache-Control", "no-cache")
				c.Header("X-Content-Type-Options", "nosniff")
				c.File(p)
				return
			}
			// Fallback check root/<reqPath> directly
			pDirect := filepath.Join(root, reqPath)
			if info, err := os.Stat(pDirect); err == nil && info.Mode().IsRegular() {
				c.Header("Cache-Control", "no-cache")
				c.Header("X-Content-Type-Options", "nosniff")
				c.File(pDirect)
				return
			}
		}
		c.Status(http.StatusNotFound)
	}

	s.router.GET("/assets/*filepath", assetHandler)
	s.router.HEAD("/assets/*filepath", assetHandler)
}
