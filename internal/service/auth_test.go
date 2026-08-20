package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/keys"
)

// writeTestKey generates an RSA key and writes it as a PKCS#8 PEM, returning
// the path. It is only used to wire up a KeySet in tests.
func writeTestKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "jwt_private.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func newTestService(t *testing.T) *AuthService {
	t.Helper()
	ks, err := keys.Load(writeTestKey(t), nil)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	cfg := &config.Config{}
	cfg.JWT.Issuer = "sleipnir-auth"
	cfg.JWT.Audience = []string{"trading-backend", "keys-service"}
	cfg.JWT.AccessTokenTTL = 15 * time.Minute
	return NewAuthService(nil, cfg, ks)
}

func TestAccessToken_RoundTrip(t *testing.T) {
	s := newTestService(t)
	u := &user.User{ID: "user-123", Email: "a@b.c", Role: "trader"}

	tokenStr, _, err := s.generateAccessToken(u)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	claims, err := s.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("sub = %q, want user-123", claims.Subject)
	}
	if claims.UserID != "user-123" {
		t.Errorf("user_id = %q, want user-123", claims.UserID)
	}
	if claims.Issuer != "sleipnir-auth" {
		t.Errorf("iss = %q, want sleipnir-auth", claims.Issuer)
	}
	if claims.Role != "trader" {
		t.Errorf("role = %q, want trader", claims.Role)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "trading-backend" {
		t.Errorf("aud = %v, want [trading-backend keys-service]", claims.Audience)
	}
	if claims.ExpiresAt == nil {
		t.Error("exp must be set")
	}
}

func TestAccessToken_SignedWithRS256(t *testing.T) {
	s := newTestService(t)
	tokenStr, _, err := s.generateAccessToken(&user.User{ID: "u1"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	tok, _, err := jwt.NewParser().ParseUnverified(tokenStr, &user.Claims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.Method.Alg() != "RS256" {
		t.Errorf("alg = %q, want RS256", tok.Method.Alg())
	}
	if _, ok := tok.Header["kid"]; !ok {
		t.Error("kid header must be present")
	}
}

func TestValidateAccessToken_RejectsHS256(t *testing.T) {
	s := newTestService(t)
	// Forge an HS256 token — must be rejected even if signed correctly.
	claims := &user.Claims{
		UserID: "u1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "sleipnir-auth",
			Subject:   "u1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("attacker-secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := s.ValidateAccessToken(forged); err == nil {
		t.Fatal("HS256 token must be rejected")
	}
}

func TestValidateAccessToken_RejectsMissingExp(t *testing.T) {
	s := newTestService(t)
	claims := &user.Claims{
		UserID:           "u1",
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "sleipnir-auth", Subject: "u1"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.keys.ActiveKID()
	signed, err := tok.SignedString(s.keys.Private())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := s.ValidateAccessToken(signed); err == nil {
		t.Fatal("token without exp must be rejected")
	}
}

func TestValidateAccessToken_RejectsWrongIssuer(t *testing.T) {
	s := newTestService(t)
	claims := &user.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "evil-issuer",
			Subject:   "u1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = s.keys.ActiveKID()
	signed, _ := tok.SignedString(s.keys.Private())
	if _, err := s.ValidateAccessToken(signed); err == nil {
		t.Fatal("wrong issuer must be rejected")
	}
}
