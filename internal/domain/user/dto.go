package user

type CreateDTO struct {
	LastName     string  `json:"last_name"`
	FirstName    string  `json:"first_name"`
	Patronymic   *string `json:"patronymic"`
	Email        string  `json:"email"`
	Password     string  `json:"password"`
	PasswordHash string  `json:"password_hash"`
}

type Login struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type Refresh struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}
