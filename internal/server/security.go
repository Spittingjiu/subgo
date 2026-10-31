package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/config"
	"github.com/Spittingjiu/subgo/internal/services/auth"
	"github.com/Spittingjiu/subgo/internal/services/source"
	"github.com/gin-gonic/gin"
)

const (
	secureManagementCookie = "__Host-subgo_session"
	legacyManagementCookie = "subgo_session" // explicit HTTP development only
	panelProxyLaunchPath   = "/panel-proxy-launch"
	panelProxyPathPrefix   = "/panel-proxy/"
)

// Integration: install globally, BEFORE auditMutations and before routes.
// It is not an alternative to requireAuth: both are needed. Host dispatch is
// enforced even for unauthenticated routes, preventing proxy-origin HTML from
// accessing login, bridge, management APIs or the management UI on this host.
func (s *Server) securityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.cfg.ValidateSecurity() != nil || s.auth.Ready() != nil {
			securityJSONError(c, http.StatusServiceUnavailable, "security configuration unavailable")
			return
		}
		if s.isPanelProxyHost(c.Request.Host) {
			panelProxyHeaders(c)
			if c.Request.URL.Path != panelProxyLaunchPath && !strings.HasPrefix(c.Request.URL.Path, panelProxyPathPrefix) {
				securityJSONError(c, http.StatusNotFound, "not found")
				return
			}
			c.Next()
			return
		}
		if _, err := s.expectedManagementOrigin(c); err != nil {
			securityJSONError(c, http.StatusMisdirectedRequest, "unrecognized management host")
			return
		}
		if managementSecurityPath(c.Request.URL.Path) {
			noStoreHeaders(c)
			if err := s.checkManagementOrigin(c); err != nil {
				securityJSONError(c, http.StatusForbidden, "cross-origin management request rejected")
				return
			}
		}
		if strings.HasPrefix(c.Request.URL.Path, panelProxyPathPrefix) && !safeMethod(c.Request.Method) {
			securityJSONError(c, http.StatusMethodNotAllowed, "legacy proxy only supports a safe redirect")
			return
		}
		c.Next()
	}
}

func managementSecurityPath(path string) bool {
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	// Public subscription URLs remain compatible with no-cookie clients.
	return !strings.HasPrefix(path, "/api/sub/") && path != "/api/version"
}

func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func noStoreHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
}

func panelProxyHeaders(c *gin.Context) {
	noStoreHeaders(c)
	c.Header("Cross-Origin-Resource-Policy", "same-origin")
	c.Header("Cross-Origin-Opener-Policy", "same-origin")
}

func securityJSONError(c *gin.Context, status int, message string) {
	noStoreHeaders(c)
	c.AbortWithStatusJSON(status, gin.H{"ok": false, "error": message})
}

func normalizedRequestHost(raw, scheme string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, "/\\?#@ \t\r\n") {
		return "", errors.New("invalid request host")
	}
	u, err := config.ParseOrigin(scheme + "://" + raw)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

func (s *Server) isPanelProxyHost(host string) bool {
	origin, err := s.cfg.PanelProxyOriginURL()
	if err != nil || origin == nil {
		return false
	}
	normalized, err := normalizedRequestHost(host, "https")
	return err == nil && normalized == origin.Host
}

func forwardedHTTPS(c *gin.Context) bool {
	// Never consume X-Forwarded-Host for an authorization decision. Proto can
	// only strengthen cookie security; canonical HTTPS is preferred below.
	return c.Request.TLS != nil || strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https")
}

func (s *Server) managementCookieSecure(c *gin.Context) bool {
	if origin, err := config.ParseOrigin(s.cfg.BaseURL); err == nil && origin.Scheme == "https" {
		return true // also covers subgo2 when nginx omits X-Forwarded-Proto
	}
	origins, _ := s.cfg.ManagementOriginURLs()
	for _, origin := range origins {
		host, err := normalizedRequestHost(c.Request.Host, origin.Scheme)
		if err == nil && host == origin.Host && origin.Scheme == "https" {
			return true
		}
	}
	return forwardedHTTPS(c)
}

// Additional origins only authorize their own Host. Main-origin -> alias and
// alias -> main-origin requests are NOT same-origin, even if both are allowed.
func (s *Server) expectedManagementOrigin(c *gin.Context) (*url.URL, error) {
	if s.isPanelProxyHost(c.Request.Host) {
		return nil, errors.New("proxy host is not a management origin")
	}
	origins, err := s.cfg.ManagementOriginURLs()
	if err != nil {
		return nil, err
	}
	for _, origin := range origins {
		host, err := normalizedRequestHost(c.Request.Host, origin.Scheme)
		if err == nil && host == origin.Host {
			return origin, nil
		}
	}
	if len(origins) > 0 {
		return nil, errors.New("unrecognized management host")
	}
	// With no canonical origin configured, explicit local development still
	// works. Production must set BaseURL and list any second UI origin.
	scheme := "http"
	if forwardedHTTPS(c) {
		scheme = "https"
	}
	host, err := normalizedRequestHost(c.Request.Host, scheme)
	if err != nil {
		return nil, err
	}
	return config.ParseOrigin(scheme + "://" + host)
}

func requestOrigin(raw string) (*url.URL, error) {
	// An actual Origin header must not contain even a trailing root slash.
	u, err := url.Parse(raw)
	if err != nil || u.Path != "" || u.RawPath != "" {
		return nil, errors.New("invalid Origin")
	}
	return config.ParseOrigin(raw)
}

func checkRequestOrigin(c *gin.Context, expected *url.URL, allowNavigation bool) error {
	origins := c.Request.Header.Values("Origin")
	sites := c.Request.Header.Values("Sec-Fetch-Site")
	if len(origins) > 1 || len(sites) > 1 {
		return errors.New("ambiguous browser provenance")
	}
	originPresent := len(origins) == 1
	if originPresent {
		origin, err := requestOrigin(origins[0])
		if err != nil || origin.String() != expected.String() {
			return errors.New("Origin mismatch")
		}
	}
	site := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Site")))
	navigation := allowNavigation && (c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead) && c.GetHeader("Sec-Fetch-Mode") == "navigate" && c.GetHeader("Sec-Fetch-Dest") == "document" && !originPresent
	if site != "" && site != "same-origin" && site != "none" {
		if !navigation || (site != "same-site" && site != "cross-site") {
			return errors.New("Fetch-Metadata mismatch")
		}
	}
	if !safeMethod(c.Request.Method) && !originPresent && site != "same-origin" {
		browserMetadata := site != "" || c.GetHeader("Sec-Fetch-Mode") != "" || c.GetHeader("Sec-Fetch-Dest") != "" || c.GetHeader("Sec-Fetch-User") != ""
		if c.GetHeader("Cookie") != "" || browserMetadata {
			return errors.New("cookie/browser write requires same-origin provenance")
		}
		// Preserve CLI/API login and the username/password machine bridge when
		// no Cookie, Origin or browser Fetch-Metadata headers are present.
	}
	return nil
}

func (s *Server) checkManagementOrigin(c *gin.Context) error {
	origin, err := s.expectedManagementOrigin(c)
	if err != nil {
		return err
	}
	return checkRequestOrigin(c, origin, false)
}

// Ambiguous same-name cookies fail closed, including Domain-cookie tossing.
func uniqueCookie(r *http.Request, name string) (string, bool) {
	value, count := "", 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			value, count = cookie.Value, count+1
		}
	}
	return value, count == 1 && value != ""
}

func (s *Server) managementCookieToken(c *gin.Context) (string, bool) {
	if _, err := s.expectedManagementOrigin(c); err != nil {
		return "", false
	}
	name := legacyManagementCookie
	if s.managementCookieSecure(c) {
		name = secureManagementCookie
	}
	return uniqueCookie(c.Request, name)
}

func (s *Server) currentManagementToken(c *gin.Context) (string, bool) {
	token, ok := s.managementCookieToken(c)
	if !ok {
		return "", false
	}
	_, ok = s.auth.Verify(token)
	return token, ok
}

// Integration: currentUser's body becomes return s.currentManagementUser(c).
func (s *Server) currentManagementUser(c *gin.Context) (string, bool) {
	token, ok := s.currentManagementToken(c)
	if !ok {
		return "", false
	}
	return s.auth.Verify(token)
}

// Integration: use this instead of the old login http.SetCookie/isHTTPS.
func (s *Server) setManagementCookie(c *gin.Context, token string) error {
	if _, err := s.expectedManagementOrigin(c); err != nil {
		return err
	}
	exp, ok := s.auth.SessionExpiration(token)
	if !ok {
		return auth.ErrInvalidSession
	}
	secure := s.managementCookieSecure(c)
	name := legacyManagementCookie
	if secure {
		name = secureManagementCookie
	}
	maxAge := int(time.Until(exp).Seconds())
	if maxAge < 1 {
		return auth.ErrInvalidSession
	}
	noStoreHeaders(c)
	http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: token, Path: "/", Expires: exp, MaxAge: maxAge, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	if secure {
		// Retire the old unprefixed cookie. Never accept it on HTTPS, where an
		// untrusted sibling origin could set a parent-domain cookie of that name.
		http.SetCookie(c.Writer, &http.Cookie{Name: legacyManagementCookie, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	return nil
}

func (s *Server) clearManagementCookie(c *gin.Context) {
	noStoreHeaders(c)
	secure := s.managementCookieSecure(c)
	name := legacyManagementCookie
	if secure {
		name = secureManagementCookie
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: name, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	if secure {
		http.SetCookie(c.Writer, &http.Cookie{Name: legacyManagementCookie, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	}
}

// Integration: logout calls this, reports 503 on DB failure, never claims a
// successful server revocation merely because a browser cookie was cleared.
func (s *Server) logoutManagementSession(c *gin.Context) error {
	if _, err := s.expectedManagementOrigin(c); err != nil {
		return err
	}
	// Parse without a DB Verify first: a DB outage must surface as failure to
	// persist revocation, not as a falsely successful "already logged out".
	token, ok := s.managementCookieToken(c)
	if ok {
		if err := s.auth.RevokeSession(token); err != nil {
			return err
		}
	} else {
		name := legacyManagementCookie
		if s.managementCookieSecure(c) {
			name = secureManagementCookie
		}
		for _, cookie := range c.Request.Cookies() {
			if cookie.Name == name && cookie.Value != "" {
				return errors.New("ambiguous session cookie")
			}
		}
	}
	s.clearManagementCookie(c)
	return nil
}

// Integration: call after building the authenticated /api router group. The
// launch route is deliberately outside that group, but only on the proxy Host.
func (s *Server) registerSecurityRoutes(api *gin.RouterGroup) {
	api.POST("/panel-proxy/ticket", s.panelProxyTicket)
	s.router.GET(panelProxyLaunchPath, s.panelProxyLaunch)
}

func (s *Server) panelProxyTicket(c *gin.Context) {
	noStoreHeaders(c)
	if err := s.checkManagementOrigin(c); err != nil {
		securityJSONError(c, http.StatusForbidden, "cross-origin management request rejected")
		return
	}
	token, ok := s.currentManagementToken(c)
	if !ok {
		securityJSONError(c, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		SourceID int64 `json:"source_id"`
	}
	if strings.TrimSpace(strings.SplitN(c.GetHeader("Content-Type"), ";", 2)[0]) != "application/json" {
		securityJSONError(c, http.StatusBadRequest, "JSON source_id required")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.SourceID <= 0 {
		securityJSONError(c, http.StatusBadRequest, "invalid source_id or JSON")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		securityJSONError(c, http.StatusBadRequest, "one JSON object required")
		return
	}
	launchURL, err := s.panelProxyLaunchURL(token, req.SourceID)
	if err != nil {
		securityJSONError(c, http.StatusBadRequest, "source unavailable or isolated panel proxy is not configured")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "url": launchURL})
}

func (s *Server) panelProxyLaunchURL(sessionToken string, sid int64) (string, error) {
	if err := s.cfg.ValidateSecurity(); err != nil {
		return "", err
	}
	origin, err := s.cfg.PanelProxyOriginURL()
	if err != nil || origin == nil {
		return "", errors.New("isolated proxy is not configured")
	}
	src, err := s.sourceSvc.Get(sid)
	if err != nil || src.Type == "local" || !src.Enabled {
		return "", errors.New("source unavailable")
	}
	if _, err := panelSourceBase(src); err != nil {
		return "", err
	}
	ticket, err := s.auth.IssuePanelProxyTicket(sessionToken, sid, origin.Host, s.cfg.EffectivePanelProxyTicketTTL())
	if err != nil {
		return "", err
	}
	launch := *origin
	launch.Path = panelProxyLaunchPath
	launch.RawQuery = url.Values{"ticket": []string{ticket}}.Encode()
	return launch.String(), nil
}

func panelProxyCookieName(sid int64) string {
	return "__Secure-subgo_proxy_" + strconv.FormatInt(sid, 10)
}

func panelProxySourcePath(sid int64) string {
	return panelProxyPathPrefix + strconv.FormatInt(sid, 10) + "/"
}

func (s *Server) panelProxyLaunch(c *gin.Context) {
	panelProxyHeaders(c)
	// No untrusted HTML/scripts are emitted by the launcher, only a redirect.
	c.Header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	if !s.isPanelProxyHost(c.Request.Host) {
		securityJSONError(c, http.StatusNotFound, "not found")
		return
	}
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["ticket"]) != 1 {
		securityJSONError(c, http.StatusBadRequest, "one launch ticket required")
		return
	}
	origin, err := s.cfg.PanelProxyOriginURL()
	if err != nil || origin == nil {
		securityJSONError(c, http.StatusServiceUnavailable, "isolated proxy unavailable")
		return
	}
	session, err := s.auth.ExchangePanelProxyTicket(query.Get("ticket"), origin.Host, s.cfg.EffectivePanelProxySessionTTL())
	if err != nil {
		securityJSONError(c, http.StatusUnauthorized, "invalid or expired launch ticket")
		return
	}
	maxAge := int(time.Until(session.Expires).Seconds())
	if maxAge < 1 {
		securityJSONError(c, http.StatusUnauthorized, "expired launch ticket")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: panelProxyCookieName(session.SourceID), Value: session.Token, Path: panelProxySourcePath(session.SourceID), Expires: session.Expires, MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	// Ticket is consumed before ANY upstream request. It never reaches upstream
	// HTML, URLs or a Referer; the browser immediately lands on a clean URL.
	c.Redirect(http.StatusSeeOther, panelProxySourcePath(session.SourceID))
}

func panelProxyScope(r *http.Request) (int64, string, bool) {
	if !strings.HasPrefix(r.URL.Path, panelProxyPathPrefix) {
		return 0, "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, panelProxyPathPrefix), "/", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	sid, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || sid <= 0 || parts[0] != strconv.FormatInt(sid, 10) || !strings.HasPrefix(r.URL.EscapedPath(), panelProxySourcePath(sid)) {
		return 0, "", false
	}
	tail := "/" + parts[1]
	if strings.ContainsAny(tail, "\\\x00\r\n") {
		return 0, "", false
	}
	for _, segment := range strings.Split(tail, "/") {
		if segment == "." || segment == ".." {
			return 0, "", false
		}
	}
	return sid, tail, true
}

// Returns false after sending a redirect/error. A management cookie is never
// proxy authorization. On the old origin only safe GET/HEAD launch redirects
// are allowed; an upstream response can only be served on the isolated Host.
func (s *Server) authorizePanelProxy(c *gin.Context) (int64, bool) {
	sid, _, ok := panelProxyScope(c.Request)
	if !ok {
		securityJSONError(c, http.StatusBadRequest, "invalid proxy source or path")
		return 0, false
	}
	if !s.isPanelProxyHost(c.Request.Host) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			securityJSONError(c, http.StatusMethodNotAllowed, "legacy proxy only supports a safe redirect")
			return 0, false
		}
		if s.checkManagementOrigin(c) != nil {
			securityJSONError(c, http.StatusForbidden, "cross-origin management request rejected")
			return 0, false
		}
		token, ok := s.currentManagementToken(c)
		if !ok {
			securityJSONError(c, http.StatusUnauthorized, "unauthorized")
			return 0, false
		}
		launchURL, err := s.panelProxyLaunchURL(token, sid)
		if err != nil {
			securityJSONError(c, http.StatusBadRequest, "source unavailable or isolated proxy is not configured")
			return 0, false
		}
		noStoreHeaders(c)
		// Intentionally discard legacy deep paths and queries: a management GET
		// is a launch, never a credentialed request to an arbitrary upstream API.
		c.Redirect(http.StatusSeeOther, launchURL)
		return 0, false
	}
	origin, err := s.cfg.PanelProxyOriginURL()
	if err != nil || origin == nil || checkRequestOrigin(c, origin, true) != nil {
		securityJSONError(c, http.StatusForbidden, "cross-origin panel write rejected")
		return 0, false
	}
	token, ok := uniqueCookie(c.Request, panelProxyCookieName(sid))
	if !ok || !s.auth.VerifyPanelProxy(token, origin.Host, sid) {
		securityJSONError(c, http.StatusUnauthorized, "panel proxy session required")
		return 0, false
	}
	return sid, true
}

var isolatedProxyClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func panelSourceBase(src source.Source) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(src.PanelURL, "/"))
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid panel base URL")
	}
	if strings.Contains(u.Path, "/api/v1/sub/") {
		u.Path, u.RawPath = "", "" // subscription URL is not the panel base
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return u, nil
}

// Integration: replace the old panelProxy body with s.serveIsolatedPanelProxy(c).
// No old cookie/HTML proxy code should remain on the reachable handler path.
func (s *Server) serveIsolatedPanelProxy(c *gin.Context) {
	sid, ok := s.authorizePanelProxy(c)
	if !ok {
		return
	}
	if c.Request.Method == http.MethodTrace || c.Request.Method == http.MethodConnect {
		securityJSONError(c, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, tail, _ := panelProxyScope(c.Request)
	if (c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead) && tail == "/.subgo-runtime.js" {
		// Same-origin external runtime keeps CSP script-src 'self' usable;
		// this reserved source path still requires its scoped proxy cookie.
		panelProxyHeaders(c)
		c.Header("Content-Type", "application/javascript; charset=utf-8")
		if c.Request.Method == http.MethodGet {
			c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(isolatedPanelRuntime(sid)))
		} else {
			c.Status(http.StatusOK)
		}
		return
	}
	src, err := s.sourceSvc.Get(sid)
	if err != nil || !src.Enabled || src.Type == "local" {
		securityJSONError(c, http.StatusNotFound, "source unavailable")
		return
	}
	base, err := panelSourceBase(src)
	if err != nil {
		securityJSONError(c, http.StatusBadGateway, "panel base unavailable")
		return
	}
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + tail
	// Preserve escaped characters in upstream paths without allowing encoded
	// separators in the credential-scoping prefix.
	if c.Request.URL.RawPath != "" {
		escapedTail := strings.TrimPrefix(c.Request.URL.EscapedPath(), strings.TrimRight(panelProxySourcePath(sid), "/"))
		target.RawPath = strings.TrimRight(base.EscapedPath(), "/") + escapedTail
	} else {
		target.RawPath = ""
	}
	target.RawQuery = c.Request.URL.RawQuery
	if err := source.AssertURLSafe(target.String()); err != nil {
		securityJSONError(c, http.StatusForbidden, "panel target rejected")
		return
	}
	var body io.Reader
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		body = c.Request.Body
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target.String(), body)
	if err != nil {
		securityJSONError(c, http.StatusBadGateway, "cannot create panel request")
		return
	}
	for _, header := range []string{"Accept", "Accept-Language", "Content-Type", "User-Agent", "Authorization", "X-Panel-Token", "X-CSRF-Token", "X-XSRF-Token", "X-Requested-With"} {
		if value := c.GetHeader(header); value != "" {
			req.Header.Set(header, value)
		}
	}
	// The external Origin is verified above; present the expected UPSTREAM
	// origin to panels which implement their own same-origin write protection.
	if c.GetHeader("Origin") != "" {
		req.Header.Set("Origin", base.Scheme+"://"+base.Host)
	}
	if c.GetHeader("Referer") != "" {
		req.Header.Set("Referer", target.String())
	}
	if cookie := filterIsolatedProxyCookie(c.GetHeader("Cookie"), sid); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if src.PanelToken != "" {
		req.Header.Set("X-Panel-Token", src.PanelToken)
		req.Header.Set("Authorization", "Bearer "+src.PanelToken)
	}
	resp, err := isolatedProxyClient.Do(req)
	if err != nil {
		// net/http errors can contain the target URL (including secrets). Never
		// echo them or record upstream token/raw-link data in diagnostics.
		securityJSONError(c, http.StatusBadGateway, "panel proxy unavailable")
		return
	}
	defer resp.Body.Close()
	copyIsolatedProxyHeaders(c, resp.Header)
	if location := resp.Header.Get("Location"); location != "" {
		rewritten, err := isolatedProxyLocation(location, base, &target, sid)
		if err != nil {
			securityJSONError(c, http.StatusBadGateway, "invalid panel redirect")
			return
		}
		c.Header("Location", rewritten)
	}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		if rewritten, ok := rewriteIsolatedProxySetCookie(raw, sid); ok {
			c.Writer.Header().Add("Set-Cookie", rewritten)
		}
	}
	panelProxyHeaders(c) // upstream cannot weaken these boundaries
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && c.Request.Method == http.MethodGet && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
		if err != nil || len(data) > 16<<20 {
			securityJSONError(c, http.StatusBadGateway, "panel response too large or incomplete")
			return
		}
		data = injectIsolatedPanelBase(data, sid)
		c.Header("Content-Length", strconv.Itoa(len(data)))
		c.Status(resp.StatusCode)
		_, _ = c.Writer.Write(data)
		return
	}
	c.Status(resp.StatusCode)
	_, _ = io.Copy(c.Writer, io.LimitReader(resp.Body, 16<<20))
}

func copyIsolatedProxyHeaders(c *gin.Context, headers http.Header) {
	blocked := map[string]bool{
		"connection": true, "keep-alive": true, "proxy-authenticate": true,
		"proxy-authorization": true, "te": true, "trailer": true,
		"transfer-encoding": true, "upgrade": true, "content-length": true,
		"set-cookie": true, "set-cookie2": true, "location": true,
		"clear-site-data": true, "service-worker-allowed": true,
		"authorization": true, "x-panel-token": true,
		"cache-control": true, "pragma": true, "referrer-policy": true,
	}
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			blocked[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range headers {
		lower := strings.ToLower(name)
		if blocked[lower] || strings.HasPrefix(lower, "access-control-") || strings.HasPrefix(lower, "x-subgo-") {
			continue
		}
		for _, value := range values {
			c.Writer.Header().Add(name, value)
		}
	}
}

func isolatedProxyLocation(raw string, base, target *url.URL, sid int64) (string, error) {
	ref, err := url.Parse(raw)
	if err != nil || ref.User != nil || ref.Opaque != "" {
		return "", errors.New("invalid redirect")
	}
	resolved := target.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", errors.New("invalid redirect scheme")
	}
	if !strings.EqualFold(resolved.Host, base.Host) {
		return resolved.String(), nil // external login/SSO, never auto-followed
	}
	path := resolved.Path
	basePath := strings.TrimRight(base.Path, "/")
	if basePath != "" && (path == basePath || strings.HasPrefix(path, basePath+"/")) {
		path = strings.TrimPrefix(path, basePath)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	resolved.Scheme, resolved.Host = "", ""
	resolved.Path = strings.TrimRight(panelProxySourcePath(sid), "/") + path
	resolved.RawPath = ""
	return resolved.String(), nil
}

func internalCookieName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "subgo_") || strings.HasPrefix(lower, "__host-subgo_") || strings.HasPrefix(lower, "__secure-subgo_") || strings.HasPrefix(lower, "__http-subgo_") || strings.HasPrefix(lower, "__host-http-subgo_")
}

func upstreamHostCookiePrefix(sid int64) string {
	return "__Secure-subgo_upstream_" + strconv.FormatInt(sid, 10) + "_"
}

func filterIsolatedProxyCookie(raw string, sid int64) string {
	r := &http.Request{Header: http.Header{"Cookie": []string{raw}}}
	var keep []string
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, upstreamHostCookiePrefix(sid)) {
			name, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(cookie.Name, upstreamHostCookiePrefix(sid)))
			if err != nil || !strings.HasPrefix(string(name), "__Host-") || internalCookieName(string(name)) {
				continue
			}
			cookie.Name = string(name)
		} else if internalCookieName(cookie.Name) {
			continue
		}
		if cookie.Valid() == nil {
			keep = append(keep, cookie.String()) // preserve quoted cookie values
		}
	}
	return strings.Join(keep, "; ")
}

// Parse attributes rather than splitting away expiry/flags. Domain is ALWAYS
// removed, paths cannot escape the selected source, Secure is strengthened.
// Ordinary HttpOnly and SameSite flags are retained so CSRF-readable cookies
// still work. Reserved internal cookie names cannot be minted by upstream.
func rewriteIsolatedProxySetCookie(raw string, sid int64) (string, bool) {
	cookie, err := http.ParseSetCookie(raw)
	if err != nil || sid <= 0 || internalCookieName(cookie.Name) {
		return "", false
	}
	// Go preserves a syntactically invalid Path in Unparsed instead of
	// returning an error. Do not silently turn an invalid explicit scope into
	// the broader default source root when dropping extension attributes.
	for _, attribute := range cookie.Unparsed {
		name, _, _ := strings.Cut(attribute, "=")
		if strings.EqualFold(strings.TrimSpace(name), "path") {
			return "", false
		}
	}
	if strings.HasPrefix(cookie.Name, "__Host-") {
		// __Host- requires Path=/, incompatible with source-path confinement.
		// Namespace it on the wire and restore its original name upstream.
		cookie.Name = upstreamHostCookiePrefix(sid) + base64.RawURLEncoding.EncodeToString([]byte(cookie.Name))
	}
	path := cookie.Path
	if path == "" || path == "/" {
		path = ""
	} else {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\r\n\x00") {
			return "", false
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == "." || segment == ".." {
				return "", false
			}
		}
	}
	cookie.Path = strings.TrimRight(panelProxySourcePath(sid), "/") + "/" + strings.TrimLeft(path, "/")
	cookie.Domain, cookie.Raw, cookie.RawExpires, cookie.Unparsed = "", "", "", nil
	cookie.Secure = true
	if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
		cookie.SameSite = http.SameSiteLaxMode
	}
	if cookie.Valid() != nil {
		return "", false
	}
	return cookie.String(), true
}

var (
	panelRootAttribute = regexp.MustCompile(`(?i)\b(src|href|action|poster)\s*=\s*(["'])(/[^"']*)["']`)
	panelRootRedirect  = regexp.MustCompile(`(?i)(?:window\.)?location\.(?:href\s*=|assign\(|replace\()\s*(["'])(/[^"']*)["']`)
	panelScriptNonce   = regexp.MustCompile(`(?i)<script\b[^>]*\bnonce\s*=\s*["']([a-zA-Z0-9+/_=-]{1,256})["']`)
)

func injectIsolatedPanelBase(body []byte, sid int64) []byte {
	if bytes.Contains(body, []byte("data-subgo-isolated-proxy")) {
		return body
	}
	prefix := strings.TrimRight(panelProxySourcePath(sid), "/")
	body = panelRootRedirect.ReplaceAllFunc(body, func(redirect []byte) []byte {
		indices := panelRootRedirect.FindSubmatchIndex(redirect)
		path := string(redirect[indices[4]:indices[5]])
		if strings.HasPrefix(path, "//") || strings.HasPrefix(path, panelProxyPathPrefix) {
			return redirect
		}
		out := append([]byte{}, redirect[:indices[4]]...)
		out = append(out, prefix...)
		return append(out, redirect[indices[4]:]...)
	})
	body = panelRootAttribute.ReplaceAllFunc(body, func(attribute []byte) []byte {
		parts := panelRootAttribute.FindSubmatch(attribute)
		path := string(parts[3])
		if strings.HasPrefix(path, "//") || strings.HasPrefix(path, panelProxyPathPrefix) {
			return attribute
		}
		return []byte(string(parts[1]) + "=" + string(parts[2]) + prefix + path + string(parts[2]))
	})
	// Real isolation comes from Host dispatch and the independent origin, NOT
	// sandbox='allow-scripts allow-same-origin' and NOT disabling all scripts.
	// Keep panel scripts functional while adapting same-origin root requests.
	nonceAttribute := ""
	if nonce := panelScriptNonce.FindSubmatch(body); len(nonce) == 2 {
		nonceAttribute = ` nonce="` + string(nonce[1]) + `"`
	}
	injection := `<base data-subgo-isolated-proxy href="` + prefix + `/"><script src="` + prefix + `/.subgo-runtime.js"` + nonceAttribute + `></script>`
	lower := bytes.ToLower(body)
	if start := bytes.Index(lower, []byte("<head")); start >= 0 {
		if end := bytes.IndexByte(body[start:], '>'); end >= 0 {
			index := start + end + 1
			result := make([]byte, 0, len(body)+len(injection))
			result = append(result, body[:index]...)
			result = append(result, injection...)
			return append(result, body[index:]...)
		}
	}
	return append([]byte(injection), body...)
}

// This adapts URL and upstream cookie names, not the trust boundary. Native
// browser same-origin policy plus Host/API dispatch supplies real isolation.
func isolatedPanelRuntime(sid int64) string {
	prefix := strings.TrimRight(panelProxySourcePath(sid), "/")
	cookiePrefix := upstreamHostCookiePrefix(sid)
	return `(function(){'use strict';
const P='` + prefix + `', C='` + cookiePrefix + `';
function r(x){try{if(typeof x!=='string')return x;const u=new URL(x,location.href);if(u.origin!==location.origin||u.pathname.startsWith('/panel-proxy/'))return x;return P+u.pathname+u.search+u.hash}catch(e){return x}}
const f=window.fetch;window.fetch=function(x,o){if(typeof x==='string')x=r(x);else if(x instanceof URL)x=r(x.href);else if(x&&x.url){const n=r(x.url);if(n!==x.url)x=new Request(n,x)}return f.call(this,x,o)};
const o=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=r(u);return o.apply(this,arguments)};
for(const k of ['pushState','replaceState']){const fn=history[k];if(fn)history[k]=function(a,b,u){return fn.call(this,a,b,u==null?u:r(u))}}
document.addEventListener('click',function(e){const a=e.target&&e.target.closest&&e.target.closest('a[href^="/"]');if(a)a.setAttribute('href',r(a.getAttribute('href')))},true);
const protectedName=n=>/^(?:subgo_|__host-subgo_|__secure-subgo_|__http-subgo_|__host-http-subgo_)/i.test(n);
function wireName(n){return C+btoa(n).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function originalName(n){try{if(!n.startsWith(C))return n;let v=n.slice(C.length).replace(/-/g,'+').replace(/_/g,'/');v+='='.repeat((4-v.length%4)%4);const d=atob(v);return d.startsWith('__Host-')&&!protectedName(d)?d:n}catch(e){return n}}
try{let p=document,dc;while(p&&!dc){dc=Object.getOwnPropertyDescriptor(p,'cookie');p=Object.getPrototypeOf(p)}if(dc&&dc.get&&dc.set)Object.defineProperty(document,'cookie',{configurable:true,get(){return dc.get.call(document).split(';').map(s=>{s=s.trim();const i=s.indexOf('=');if(i<0)return '';const n=originalName(s.slice(0,i));return protectedName(n)?'':n+s.slice(i)}).filter(Boolean).join('; ')},set(v){v=String(v);const parts=v.split(';'),i=parts[0].indexOf('=');if(i<0)return;const n=parts[0].slice(0,i).trim();if(protectedName(n))return;let path='';const attrs=parts.slice(1).filter(a=>{const j=a.indexOf('='),key=(j<0?a:a.slice(0,j)).trim().toLowerCase();if(key==='domain')return false;if(key==='path'){path=j<0?'':a.slice(j+1).trim();return false}return true});if(!path.startsWith('/')||path.includes('\\')||path.split('/').some(s=>s==='.'||s==='..'))path='';const name=n.startsWith('__Host-')?wireName(n):n;dc.set.call(document,name+parts[0].slice(i)+'; '+attrs.join('; ')+'; Path='+P+'/'+path.replace(/^\/+/, '')+'; Secure')}})}catch(e){}
})();`
}
