package server

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Spittingjiu/subgo/internal/services/subscription"
	"github.com/Spittingjiu/subgo/internal/subconv"
	"github.com/gin-gonic/gin"
)

// registerConversionRoutes must be attached to the existing authenticated API
// group. The caller's management Host/origin security middleware remains in
// force; these read-only handlers also reject cross-origin browser requests.
func (s *Server) registerConversionRoutes(api *gin.RouterGroup) {
	readOnly := api.Group("", s.conversionReadOnly())
	readOnly.POST("/subscriptions/preview", s.previewSubscriptionConversion)
	readOnly.GET("/subscriptions/:id/diagnostics", s.subscriptionConversionDiagnostics)
}

func (s *Server) conversionReadOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		// POST here is a calculation, not a mutation. Prevent the existing global
		// auditMutations middleware from writing an access/audit row for it.
		c.Set(auditDoneKey, true)
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Header("Referrer-Policy", "no-referrer")
		if site := strings.ToLower(c.GetHeader("Sec-Fetch-Site")); site != "" && site != "same-origin" && site != "none" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"ok": false, "error": "cross-origin request rejected"})
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" && !s.conversionOriginMatches(c, origin) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"ok": false, "error": "cross-origin request rejected"})
			return
		}
		c.Next()
	}
}

func (s *Server) conversionOriginMatches(c *gin.Context, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	scheme := "http"
	if isHTTPS(c) {
		scheme = "https"
	} else if base, err := url.Parse(s.cfg.BaseURL); err == nil && base.Scheme == "https" {
		// Canonical HTTPS remains HTTPS behind a subgo2 reverse proxy that does
		// not supply X-Forwarded-Proto. This is not a cross-origin CORS allowlist.
		scheme = "https"
	}
	target, err := url.Parse(scheme + "://" + c.Request.Host)
	if err != nil || target.Host == "" {
		return false
	}
	return u.Scheme == target.Scheme && strings.EqualFold(u.Hostname(), target.Hostname()) && conversionOriginPort(u) == conversionOriginPort(target)
}

func conversionOriginPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (s *Server) previewSubscriptionConversion(c *gin.Context) {
	var req struct {
		NodeHashes           *[]string `json:"node_hashes"`
		SourceIDs            []int64   `json:"source_ids"`
		AutoPruneUnreachable bool      `json:"auto_prune_unreachable"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 256*1024)
	if err := c.ShouldBindJSON(&req); err != nil || req.NodeHashes == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "explicit node_hashes array required"})
		return
	}
	if !subscription.ValidatePreviewScope(*req.NodeHashes, req.SourceIDs) {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid or oversized preview scope"})
		return
	}
	report, err := s.subs.PreviewContext(c.Request.Context(), *req.NodeHashes, req.SourceIDs, req.AutoPruneUnreachable, s.clashTemplate())
	if err != nil {
		conversionReadError(c, err)
		return
	}
	setConversionHeaders(c, report)
	c.JSON(http.StatusOK, gin.H{"ok": true, "report": report})
}

func (s *Server) subscriptionConversionDiagnostics(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid subscription id"})
		return
	}
	report, err := s.subs.DiagnosticsContext(c.Request.Context(), id, s.clashTemplate())
	if err != nil {
		conversionReadError(c, err)
		return
	}
	setConversionHeaders(c, report)
	c.JSON(http.StatusOK, gin.H{"ok": true, "report": report})
}

func conversionReadError(c *gin.Context, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"ok": false, "error": "subscription not found"})
		return
	}
	// Database errors and canceled request details can contain sensitive state.
	c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "conversion data unavailable"})
}

// Parent integration: subClash can call subs.ClashWithReport and this helper
// instead of subs.Clash to expose non-sensitive public export counts as well.
func setConversionHeaders(c *gin.Context, report subconv.Report) {
	c.Header("X-Subgo-Input-Count", strconv.Itoa(report.InputCount))
	c.Header("X-Subgo-Converted-Count", strconv.Itoa(report.ConvertedCount))
	c.Header("X-Subgo-Skipped-Count", strconv.Itoa(report.SkippedCount))
	c.Header("X-Subgo-Conversion-Valid", strconv.FormatBool(report.Valid))
}
