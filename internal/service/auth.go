package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/keys"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

// validSigningMethods are the only JWT algorithms accepted on issuance and
// verification. HS*, none and EC are rejected per the auth-service contract.
var validSigningMethods = []string{"RS256", "RS384", "RS512"}

type AuthService struct {
	repo user.Repository
	cfg  *config.Config
	keys *keys.KeySet
}

func NewAuthService(repo user.Repository, cfg *config.Config, ks *keys.KeySet) *AuthService {
	return &AuthService{repo: repo, cfg: cfg, keys: ks}
}

func (s *AuthService) Register(ctx context.Context, dto *user.CreateDTO) (*user.UserPreview, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(dto.Password), 12)
	if err != nil {
		return nil, err
	}

	dto.PasswordHash = string(hash)

	u, err := s.repo.Create(ctx, *dto)
	if err != nil {
		return nil, err
	}

	return toUserResponse(u), nil
}

func (s *AuthService) Login(ctx context.Context, req *user.Login) (*user.TokenResponse, *user.AuthUser, error) {
	u, err := s.repo.GetByEmail(ctx, req.Email)
	if errors.Is(err, user.ErrNotFound) {
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	tokens, err := s.issueTokenPair(ctx, u)
	if err != nil {
		return nil, nil, err
	}

	// Best-effort: a failed last_login write must not deny a valid login.
	_ = s.repo.UpdateLastLogin(ctx, u.ID)

	return tokens, toAuthUser(u), nil
}

func (s *AuthService) Refresh(ctx context.Context, req *user.Refresh) (*user.TokenResponse, error) {
	rt, err := s.repo.GetRefreshToken(ctx, req.RefreshToken)
	if errors.Is(err, user.ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.repo.DeleteRefreshToken(ctx, req.RefreshToken)
		return nil, ErrInvalidToken
	}

	u, err := s.repo.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	if err := s.repo.DeleteRefreshToken(ctx, req.RefreshToken); err != nil {
		return nil, err
	}

	return s.issueTokenPair(ctx, u)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.repo.DeleteRefreshToken(ctx, refreshToken)
}

func (s *AuthService) ValidateAccessToken(tokenStr string) (*user.Claims, error) {
	claims := &user.Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, s.keyfunc,
		jwt.WithValidMethods(validSigningMethods),
		jwt.WithIssuer(s.cfg.JWT.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// keyfunc resolves the RSA public key for verification using the token's `kid`
// header, which lets retired keys keep validating during rotation.
func (s *AuthService) keyfunc(t *jwt.Token) (interface{}, error) {
	kid, _ := t.Header["kid"].(string)
	pub, ok := s.keys.PublicKeyByKID(kid)
	if !ok {
		return nil, fmt.Errorf("%w: unknown key id %q", ErrInvalidToken, kid)
	}
	return pub, nil
}

func (s *AuthService) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return s.repo.GetByID(ctx, id)
}

// ---- internal helpers ----

func (s *AuthService) issueTokenPair(ctx context.Context, u *user.User) (*user.TokenResponse, error) {
	accessToken, expiresAt, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.NewString()
	refreshExpiresAt := time.Now().Add(s.cfg.JWT.RefreshTokenTTL)
	if err := s.repo.SaveRefreshToken(ctx, u.ID, refreshToken, refreshExpiresAt); err != nil {
		return nil, err
	}

	return &user.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
	}, nil
}

func (s *AuthService) generateAccessToken(u *user.User) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.cfg.JWT.AccessTokenTTL)
	claims := &user.Claims{
		UserID: u.ID,
		Email:  u.Email,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.JWT.Issuer,
			Audience:  jwt.ClaimStrings(s.cfg.JWT.Audience),
			Subject:   u.ID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keys.ActiveKID()
	signed, err := token.SignedString(s.keys.Private())
	return signed, expiresAt, err
}

func toUserResponse(u *user.User) *user.UserPreview {
	return &user.UserPreview{
		ID:         u.ID,
		Email:      u.Email,
		FirstName:  u.FirstName,
		LastName:   u.LastName,
		Patronymic: u.Patronymic,
		CreatedAt:  u.CreatedAt,
	}
}

func toAuthUser(u *user.User) *user.AuthUser {
	return &user.AuthUser{
		UserID: u.ID,
		Email:  u.Email,
		Name:   u.DisplayName(),
		Role:   u.Role,
	}
}
