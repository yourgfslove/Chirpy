package Api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/yourgfslove/serverStudy/internal/auth"
	"github.com/yourgfslove/serverStudy/internal/database"
	"net/http"
	"net/mail"
	"strings"
)

func validateChirp(body string) (string, error) {
	if len(body) > 140 {
		return "", errors.New("body too long")
	}
	return badWordreplace(body), nil
}

func respondWithError(w http.ResponseWriter, status int, err string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResp{err})
}

func respondWithJSON(w http.ResponseWriter, status int, resp interface{}) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func badWordreplace(s string) string {
	badwords := map[string]bool{
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}
	sepString := strings.Split(s, " ")
	for i, word := range sepString {
		if badwords[strings.ToLower(word)] {
			sepString[i] = "****"
		}
	}
	return strings.Join(sepString, " ")
}

func emailValidation(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func (api *API) NewRefreshTokenForUser(userID uuid.UUID) (string, error) {
	RefreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		return "", errors.New("cannot generate new refresh token")
	}
	err = api.DB.NewRefreshForUser(context.Background(), database.NewRefreshForUserParams{UserID: userID, Token: RefreshToken})
	if err != nil {
		return "", err
	}
	return RefreshToken, nil
}
