package auth

import (
	"errors"
	"net/http"
	"strings"
)

var errorMessage = errors.New("Invalid token")

const prefix = "Bearer"

func GetToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errorMessage
	}
	if !strings.HasPrefix(authHeader, prefix) {
		return "", errorMessage
	}
	token := strings.TrimSpace(authHeader[len(prefix):])
	if token == "" {
		return "", errorMessage
	}
	return token, nil
}
