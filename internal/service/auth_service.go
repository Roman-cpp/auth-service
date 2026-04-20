package service

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain"
	"github.com/krypton/auth-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type AuthService struct {
	repo *repository.UserRepository
	cfg  *config.Config
}

func NewAuthService(repo *repository.UserRepository, cfg *config.Config) *AuthService {
	return &AuthService{repo: repo, cfg: cfg}
}

// Register создаёт нового пользователя.
func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.UserResponse, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		return nil, err
	}

	user, err := s.repo.CreateUser(ctx, req.Email, string(hash))
	if err != nil {
		return nil, err // ErrEmailTaken пробрасывается наверх
	}

	return toUserResponse(user), nil
}

// Login проверяет учётные данные и возвращает пару токенов.
func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.TokenResponse, error) {
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return s.issueTokenPair(ctx, user)
}

// Refresh выдаёт новую пару токенов по refresh-токену (с ротацией).
func (s *AuthService) Refresh(ctx context.Context, req *domain.RefreshRequest) (*domain.TokenResponse, error) {
	rt, err := s.repo.GetRefreshToken(ctx, req.RefreshToken)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.repo.DeleteRefreshToken(ctx, req.RefreshToken)
		return nil, ErrInvalidToken
	}

	user, err := s.repo.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}

	// Ротация: удаляем старый refresh-токен перед выдачей нового
	if err := s.repo.DeleteRefreshToken(ctx, req.RefreshToken); err != nil {
		return nil, err
	}

	return s.issueTokenPair(ctx, user)
}

// Logout инвалидирует конкретный refresh-токен.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.repo.DeleteRefreshToken(ctx, refreshToken)
}

// ValidateAccessToken проверяет JWT и возвращает claims.
func (s *AuthService) ValidateAccessToken(tokenStr string) (*domain.Claims, error) {
	claims := &domain.Claims{}
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

// GetUserByID возвращает пользователя по ID.
func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.UserResponse, error) {
	user, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return toUserResponse(user), nil
}

// ---- internal helpers ----

func (s *AuthService) issueTokenPair(ctx context.Context, user *domain.User) (*domain.TokenResponse, error) {
	accessToken, expiresAt, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken := uuid.NewString()
	refreshExpiresAt := time.Now().Add(s.cfg.JWT.RefreshTokenTTL)
	if err := s.repo.SaveRefreshToken(ctx, user.ID, refreshToken, refreshExpiresAt); err != nil {
		return nil, err
	}

	return &domain.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
	}, nil
}

func (s *AuthService) generateAccessToken(user *domain.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.cfg.JWT.AccessTokenTTL)
	claims := &domain.Claims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.JWT.Secret))
	return signed, expiresAt, err
}

func toUserResponse(u *domain.User) *domain.UserResponse {
	return &domain.UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
	}
}
