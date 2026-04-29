package service

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type AuthService struct {
	repo user.Repository
	cfg  *config.Config
}

func NewAuthService(repo user.Repository, cfg *config.Config) *AuthService {
	return &AuthService{repo: repo, cfg: cfg}
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

func (s *AuthService) Login(ctx context.Context, req *user.Login) (*user.TokenResponse, *user.UserPreview, error) {
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

	return tokens, toUserResponse(u), nil
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
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(s.cfg.JWT.Secret), nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
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
	expiresAt := time.Now().Add(s.cfg.JWT.AccessTokenTTL)
	claims := &user.Claims{
		UserID: u.ID,
		Email:  u.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   u.ID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.JWT.Secret))
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
