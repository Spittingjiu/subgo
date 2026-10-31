package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	MaxPanelProxyTicketTTL  = 2 * time.Minute
	MaxPanelProxySessionTTL = 30 * time.Minute
)

var ErrInvalidProxyTicket = errors.New("invalid or expired panel launch ticket")

// PanelProxySession is emitted only by an atomic, one-time ticket exchange.
// The token must be put in a Secure HttpOnly host-only cookie, never a URL.
type PanelProxySession struct {
	Token    string
	SourceID int64
	Expires  time.Time
}

func normalizeProxyHost(host string) (string, bool) {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\?#@ \t\r\n") {
		return "", false
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Hostname() == "" || strings.HasSuffix(host, ":") || strings.HasSuffix(u.Hostname(), ".") {
		return "", false
	}
	name, port := strings.ToLower(u.Hostname()), u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		if n == 443 {
			port = ""
		} else {
			port = strconv.Itoa(n)
		}
	}
	if port != "" {
		return net.JoinHostPort(name, port), true
	}
	if strings.Contains(name, ":") {
		return "[" + name + "]", true
	}
	return name, true
}

// IssuePanelProxyTicket requires a LIVE management session. Only the digest of
// the 256-bit random ticket is stored, together with its exact source, proxy
// host, generation and parent token hash/expiry. It cannot become a login token.
func (s *Service) IssuePanelProxyTicket(sessionToken string, sourceID int64, host string, ttl time.Duration) (string, error) {
	claims, ok := s.managementClaims(sessionToken)
	if !ok {
		return "", ErrInvalidSession
	}
	host, ok = normalizeProxyHost(host)
	if !ok || sourceID <= 0 || ttl < time.Second || ttl > MaxPanelProxyTicketTTL {
		return "", errors.New("invalid panel launch scope or lifetime")
	}
	now := s.now().UTC()
	exp := now.Add(ttl).Unix()
	if claims.Expires < exp {
		exp = claims.Expires
	}
	if exp <= now.Unix() {
		return "", ErrInvalidSession
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", errors.New("cannot create panel launch ticket")
	}
	ticket := base64.RawURLEncoding.EncodeToString(bytes)
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM auth_proxy_tickets WHERE expires_at<=?`, now.Unix()); err != nil {
		return "", err
	}
	// Recheck the snapshot inside the INSERT: a concurrent account change or
	// logout after verification must not create a newly valid ticket.
	result, err := tx.Exec(`INSERT INTO auth_proxy_tickets(ticket_hash,source_id,host,username,session_epoch,session_hash,session_expires_at,expires_at,created_at)
		SELECT ?,s.id,?,a.username,a.session_epoch,?,?,?,? FROM admin_settings a JOIN sources s ON s.id=?
		WHERE a.id=1 AND a.username=? AND a.session_epoch=? AND s.source_type!='local' AND s.enabled=1
		AND NOT EXISTS(SELECT 1 FROM auth_revoked_sessions WHERE token_hash=? AND expires_at>?)`,
		tokenHash(ticket), host, tokenHash(sessionToken), claims.Expires, exp, now.Format(time.RFC3339), sourceID, claims.Username, claims.Epoch, tokenHash(sessionToken), now.Unix())
	if err != nil {
		return "", err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", ErrInvalidSession
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return ticket, nil
}

// ExchangePanelProxyTicket consumes exactly once via DELETE ... RETURNING.
// Wrong Host/purpose, expiry, disabled source, generation changes or parent
// logout are rejected inside that same atomic SQL operation. Invalid attempts
// against another Host do not consume an otherwise usable ticket.
func (s *Service) ExchangePanelProxyTicket(ticket, host string, ttl time.Duration) (PanelProxySession, error) {
	var result PanelProxySession
	if err := s.Ready(); err != nil {
		return result, err
	}
	bytes, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(bytes) != 32 {
		return result, ErrInvalidProxyTicket
	}
	host, ok := normalizeProxyHost(host)
	if !ok || ttl < time.Second || ttl > MaxPanelProxySessionTTL {
		return result, ErrInvalidProxyTicket
	}
	now := s.now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var claims tokenClaims
	var ticketExpiry int64
	err = tx.QueryRow(`DELETE FROM auth_proxy_tickets
		WHERE ticket_hash=? AND host=? AND expires_at>? AND session_expires_at>?
		AND username=(SELECT username FROM admin_settings WHERE id=1)
		AND session_epoch=(SELECT session_epoch FROM admin_settings WHERE id=1)
		AND source_id IN (SELECT id FROM sources WHERE source_type!='local' AND enabled=1)
		AND NOT EXISTS(SELECT 1 FROM auth_revoked_sessions r WHERE r.token_hash=auth_proxy_tickets.session_hash AND r.expires_at>?)
		RETURNING source_id,username,session_epoch,session_hash,session_expires_at,expires_at`,
		tokenHash(ticket), host, now.Unix(), now.Unix(), now.Unix()).Scan(&claims.SourceID, &claims.Username, &claims.Epoch, &claims.ParentHash, &claims.ParentExpires, &ticketExpiry)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrInvalidProxyTicket
	}
	if err != nil {
		return result, err
	}
	claims.Host = host
	claims.Expires = now.Add(ttl).Unix()
	if claims.ParentExpires < claims.Expires {
		claims.Expires = claims.ParentExpires
	}
	result.Token = s.signClaims(claims, panelProxyPurpose)
	if result.Token == "" {
		return PanelProxySession{}, errors.New("cannot create panel proxy session")
	}
	result.SourceID, result.Expires = claims.SourceID, time.Unix(claims.Expires, 0).UTC()
	if err := tx.Commit(); err != nil {
		return PanelProxySession{}, err
	}
	return result, nil
}

func (s *Service) VerifyPanelProxy(token, host string, sourceID int64) bool {
	claims, ok := s.decodeClaims(token, panelProxyPurpose)
	if !ok {
		return false
	}
	host, ok = normalizeProxyHost(host)
	if !ok || sourceID <= 0 || claims.SourceID != sourceID || claims.Host != host || claims.ParentExpires <= s.now().Unix() || claims.Expires > claims.ParentExpires {
		return false
	}
	parentHash, err := hex.DecodeString(claims.ParentHash)
	if err != nil || len(parentHash) != 32 {
		return false
	}
	return s.claimsCurrent(claims, token)
}
