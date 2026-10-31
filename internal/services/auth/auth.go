package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionLifetime   = 7 * 24 * time.Hour
	managementPurpose = "management-session-v2"
	panelProxyPurpose = "panel-proxy-session-v2"
	tokenVersion      = 2
	maxTokenLength    = 4096
)

var (
	ErrMissingSessionSecret = errors.New("SUBGO_SESSION_SECRET is required")
	ErrInvalidSession       = errors.New("invalid session")
	ErrInvalidCredentials   = errors.New("invalid username or password")
)

type Service struct {
	db      *sql.DB
	secret  []byte
	initErr error
	now     func() time.Time
}

type Admin struct {
	Username         string `json:"username"`
	LogRetentionDays int    `json:"log_retention_days"`
}

// The purpose is authenticated twice: in the payload and in the HMAC domain.
// Management and proxy cookies cannot be exchanged even with the same secret.
// The legacy username|expiry|nonce format is deliberately no longer accepted.
type tokenClaims struct {
	Version       int    `json:"v"`
	Purpose       string `json:"purpose"`
	Username      string `json:"username"`
	Epoch         int64  `json:"epoch"`
	Expires       int64  `json:"exp"`
	Nonce         string `json:"nonce"`
	SourceID      int64  `json:"source_id,omitempty"`
	Host          string `json:"host,omitempty"`
	ParentHash    string `json:"parent_hash,omitempty"`
	ParentExpires int64  `json:"parent_exp,omitempty"`
}

// New keeps the original API, but fails closed for an absent secret. Call
// Ready (and config.ValidateSecurity) at startup to surface configuration
// errors before serving HTTP. No random ephemeral or public fallback is used.
func New(db *sql.DB, secret string) *Service {
	s := &Service{db: db, secret: []byte(secret), now: time.Now}
	if strings.TrimSpace(secret) == "" {
		s.initErr = ErrMissingSessionSecret
	} else if db == nil {
		s.initErr = errors.New("auth database is required")
	}
	return s
}

func (s *Service) Ready() error {
	if s == nil {
		return errors.New("auth service is required")
	}
	return s.initErr
}

func (s *Service) credentials(username, password string) (string, int64, error) {
	if err := s.Ready(); err != nil {
		return "", 0, err
	}
	var u, hash string
	var epoch int64
	if err := s.db.QueryRow(`SELECT username,password_hash,session_epoch FROM admin_settings WHERE id=1`).Scan(&u, &hash, &epoch); err != nil {
		return "", 0, err
	}
	if username != u || epoch <= 0 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", 0, ErrInvalidCredentials
	}
	return u, epoch, nil
}

// CheckCredentials is for the password-authenticated, no-cookie machine
// bridge. It checks credentials without unnecessarily issuing a browser token.
func (s *Service) CheckCredentials(username, password string) error {
	_, _, err := s.credentials(username, password)
	return err
}

func (s *Service) Login(username, password string) (string, error) {
	u, epoch, err := s.credentials(username, password)
	if err != nil {
		return "", err
	}
	// Use the exact generation whose password was verified. Looking up a new
	// generation after bcrypt would let a concurrent password reset resurrect
	// a session authenticated using the old password.
	token := s.signClaims(tokenClaims{Username: u, Epoch: epoch, Expires: s.now().Add(SessionLifetime).Unix()}, managementPurpose)
	if token == "" {
		return "", errors.New("cannot create session")
	}
	return token, nil
}

// Sign remains source-compatible, but can only sign for the current account
// and persistent generation. Missing config/DB/entropy fails closed (empty).
func (s *Service) Sign(username string, exp time.Time) string {
	if s.Ready() != nil || !exp.After(s.now()) {
		return ""
	}
	var u string
	var epoch int64
	if err := s.db.QueryRow(`SELECT username,session_epoch FROM admin_settings WHERE id=1`).Scan(&u, &epoch); err != nil || u != username || epoch <= 0 {
		return ""
	}
	return s.signClaims(tokenClaims{Username: u, Epoch: epoch, Expires: exp.Unix()}, managementPurpose)
}

func (s *Service) signClaims(claims tokenClaims, purpose string) string {
	if s.Ready() != nil {
		return ""
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	claims.Version, claims.Purpose = tokenVersion, purpose
	claims.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	payload, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(purpose + "\x00"))
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Service) decodeClaims(token, purpose string) (tokenClaims, bool) {
	var claims tokenClaims
	if s.Ready() != nil || len(token) == 0 || len(token) > maxTokenLength {
		return claims, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != sha256.Size {
		return claims, false
	}
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(purpose + "\x00"))
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) || json.Unmarshal(payload, &claims) != nil {
		return tokenClaims{}, false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(claims.Nonce)
	if claims.Version != tokenVersion || claims.Purpose != purpose || claims.Username == "" || claims.Epoch <= 0 || claims.Expires <= s.now().Unix() || err != nil || len(nonce) != 16 {
		return tokenClaims{}, false
	}
	return claims, true
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// claimsCurrent queries live persisted state on every authorization. It never
// relies on a process-local cached epoch or revocation set.
func (s *Service) claimsCurrent(claims tokenClaims, token string) bool {
	var username string
	var epoch int64
	var revoked, sourceAllowed int
	err := s.db.QueryRow(`SELECT username,session_epoch,
		EXISTS(SELECT 1 FROM auth_revoked_sessions WHERE expires_at>? AND (token_hash=? OR token_hash=?)),
		(?=0 OR EXISTS(SELECT 1 FROM sources WHERE id=? AND source_type!='local' AND enabled=1))
		FROM admin_settings WHERE id=1`, s.now().Unix(), tokenHash(token), claims.ParentHash, claims.SourceID, claims.SourceID).Scan(&username, &epoch, &revoked, &sourceAllowed)
	return err == nil && username == claims.Username && epoch == claims.Epoch && revoked == 0 && sourceAllowed == 1
}

func (s *Service) managementClaims(token string) (tokenClaims, bool) {
	claims, ok := s.decodeClaims(token, managementPurpose)
	if !ok || claims.SourceID != 0 || claims.Host != "" || claims.ParentHash != "" || claims.ParentExpires != 0 {
		return tokenClaims{}, false
	}
	return claims, s.claimsCurrent(claims, token)
}

func (s *Service) Verify(token string) (string, bool) {
	claims, ok := s.managementClaims(token)
	if !ok {
		return "", false
	}
	return claims.Username, true
}

func (s *Service) SessionExpiration(token string) (time.Time, bool) {
	claims, ok := s.managementClaims(token)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(claims.Expires, 0).UTC(), true
}

// RevokeSession is idempotent, and revokes only the supplied management token,
// not every device. Invalid/expired tokens have nothing left to revoke. Proxy
// credentials cannot be submitted here as a management session.
func (s *Service) RevokeSession(token string) error {
	if err := s.Ready(); err != nil {
		return err
	}
	claims, ok := s.decodeClaims(token, managementPurpose)
	if !ok || claims.SourceID != 0 || claims.ParentHash != "" || claims.Host != "" {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	if _, err := tx.Exec(`DELETE FROM auth_revoked_sessions WHERE expires_at<=?`, now.Unix()); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO auth_revoked_sessions(token_hash,expires_at,revoked_at) VALUES(?,?,?)
		ON CONFLICT(token_hash) DO UPDATE SET expires_at=MAX(expires_at,excluded.expires_at)`, tokenHash(token), claims.Expires, now.Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Admin() (Admin, error) {
	var a Admin
	err := s.db.QueryRow(`SELECT username,COALESCE(log_retention_days,30) FROM admin_settings WHERE id=1`).Scan(&a.Username, &a.LogRetentionDays)
	return a, err
}

// Retention-only updates never change session_epoch.
func (s *Service) SetLogRetention(days int) error {
	if days < 0 {
		days = 0
	}
	if days > 3650 {
		days = 3650
	}
	_, err := s.db.Exec(`UPDATE admin_settings SET log_retention_days=?,updated_at=? WHERE id=1`, days, s.now().UTC().Format(time.RFC3339))
	return err
}

func (s *Service) UpdateAdmin(username, password string) error {
	_, err := s.UpdateAdminWithResult(username, password)
	return err
}

// UpdateAdminWithResult reports whether credentials were updated so the HTTP
// layer can clear its cookie and request reauthentication. An unchanged username
// with no password is a no-op, preserving the legacy retention-only caller.
// Each real username/password update and epoch increment is one SQL statement.
func (s *Service) UpdateAdminWithResult(username, password string) (bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return false, errors.New("username required")
	}
	now := s.now().UTC().Format(time.RFC3339)
	var result sql.Result
	var err error
	if password == "" {
		result, err = s.db.Exec(`UPDATE admin_settings SET username=?,session_epoch=session_epoch+1,updated_at=? WHERE id=1 AND username<>?`, username, now, username)
	} else {
		hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if e != nil {
			return false, e
		}
		result, err = s.db.Exec(`UPDATE admin_settings SET username=?,password_hash=?,session_epoch=session_epoch+1,updated_at=? WHERE id=1`, username, string(hash), now)
	}
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		var exists int
		if err := s.db.QueryRow(`SELECT 1 FROM admin_settings WHERE id=1`).Scan(&exists); err != nil {
			return false, err
		}
	}
	return n > 0, nil
}
