package auth

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

const MaxLengthToCrypt = 72

func HashPassword(password string) (string, error) {
	if len([]byte(password)) > MaxLengthToCrypt || len([]byte(password)) < 1 {
		return "", errors.New("wrong password length")
	}
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPass), nil
}

func VerifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
