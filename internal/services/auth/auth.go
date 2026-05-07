package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	db     *sql.DB
	secret []byte
}

type Admin struct {
	Username string `json:"username"`
}

func New(db *sql.DB, secret string) *Service {
	if secret == "" {
		log.Println("[WARNING] auth.New received empty session secret; using insecure fallback — configure SUBGO_SESSION_SECRET")
		secret = "subgo-dev-secret-change-me"
	}
	return &Service{db: db, secret: []byte(secret)}
}

func (s *Service) Login(username, password string) (string, error) {
	var u, h string
	if err := s.db.QueryRow(`SELECT username,password_hash FROM admin_settings WHERE id=1`).Scan(&u, &h); err != nil {
		return "", err
	}
	if username != u || bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) != nil {
		return "", errors.New("invalid username or password")
	}
	return s.Sign(u, time.Now().Add(7*24*time.Hour)), nil
}

func (s *Service) Sign(username string, exp time.Time) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	payload := fmt.Sprintf("%s|%d|%s", username, exp.Unix(), base64.RawURLEncoding.EncodeToString(nonce))
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func (s *Service) Verify(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	payload := string(pb)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return "", false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 3 {
		return "", false
	}
	var exp int64
	if _, err := fmt.Sscanf(fields[1], "%d", &exp); err != nil {
		return "", false
	}
	if time.Now().Unix() > exp {
		return "", false
	}
	return fields[0], true
}

func (s *Service) Admin() (Admin, error) {
	var u string
	err := s.db.QueryRow(`SELECT username FROM admin_settings WHERE id=1`).Scan(&u)
	return Admin{Username: u}, err
}

func (s *Service) UpdateAdmin(username, password string) error {
	if strings.TrimSpace(username) == "" {
		return errors.New("username required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if password == "" {
		_, err := s.db.Exec(`UPDATE admin_settings SET username=?, updated_at=? WHERE id=1`, username, now)
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE admin_settings SET username=?, password_hash=?, updated_at=? WHERE id=1`, username, string(h), now)
	return err
}
