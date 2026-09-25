package passhash

import "golang.org/x/crypto/bcrypt"

// Cost — bcrypt cost для паролей пользователей.
const Cost = 12

func Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), Cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
