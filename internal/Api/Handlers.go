package Api

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/yourgfslove/serverStudy/internal/auth"
	"github.com/yourgfslove/serverStudy/internal/database"
	"net/http"
	"time"
)

func (api *API) DeleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetKey(r.Header, "Bearer")
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing token")
		return
	}

	userID, err := auth.ValidateJWT(token, api.Secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	ChirpId, err := uuid.Parse(r.PathValue("ChirpId"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid ChirpId")
		return
	}

	Chirp, err := api.DB.GetOneChirp(context.Background(), ChirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "chirp does not exist")
		return
	}

	if Chirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "you are not an owner of this Chirp")
		return
	}

	err = api.DB.ChirpDeleteByID(context.Background(), Chirp.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
	}
	respondWithJSON(w, http.StatusNoContent, nil)
}

func (api *API) ResetHandler(w http.ResponseWriter, r *http.Request) {
	if api.Platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	err := api.DB.Reset(context.Background())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte("fileserver reset success"))
}

func (api *API) UsersHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	dat := CreateUsersRequest{}
	err := decoder.Decode(&dat)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	if !emailValidation(dat.Email) {
		respondWithError(w, http.StatusBadRequest, "email validation failed")
		return
	}
	hashedPassword, err := auth.HashPassword(dat.Password)
	User, err := api.DB.CreateUser(context.Background(), database.CreateUserParams{
		Email:          dat.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusCreated, User)
}

func (api *API) ChirpsCreateHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	dat := CreateChirpsRequest{}
	if err := decoder.Decode(&dat); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	defer r.Body.Close()

	token, err := auth.GetKey(r.Header, "Bearer")
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid token: "+err.Error())
		return
	}
	TokenUserID, err := auth.ValidateJWT(token, api.Secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Token: "+err.Error())
		return
	}
	if dat.UserId != TokenUserID {
		respondWithError(w, http.StatusUnauthorized, "invalid token:")
		return
	}
	dat.Body, err = validateChirp(dat.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Chirp body")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	Chirp, err := api.DB.CreateChirp(context.Background(), database.CreateChirpParams{
		Body:   dat.Body,
		UserID: dat.UserId,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "cannot create Chirp")
		return
	}
	respondWithJSON(w, http.StatusCreated, Chirp)
}

func (api *API) GetChirpsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("author_id")
	var chirps []database.Chirp
	var err error
	if userID == "" {
		chirps, err = api.DB.GetAllChirps(context.Background())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		parsedID, err := uuid.Parse(userID)
		if err != nil {
			respondWithError(w, http.StatusNotFound, err.Error())
			return
		}
		chirps, err = api.DB.GetChirpsByUserID(context.Background(), parsedID)
		if err != nil {
			respondWithError(w, http.StatusNotFound, err.Error())
		}
	}
	respondWithJSON(w, http.StatusOK, chirps)
}

func (api *API) GetChirpHandler(w http.ResponseWriter, r *http.Request) {
	ChirpId, err := uuid.Parse(r.PathValue("ChirpId"))
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	Chirp, err := api.DB.GetOneChirp(context.Background(), ChirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, Chirp)
}

func (api *API) LoginHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	dat := AuthUsersRequest{}
	err := decoder.Decode(&dat)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	if !emailValidation(dat.Email) {
		respondWithError(w, http.StatusBadRequest, "email validation failed")
		return
	}
	user, err := api.DB.GetUserByEmail(context.Background(), dat.Email)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}
	if auth.VerifyPassword(dat.Password, user.HashedPassword) != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid password or email")
		return
	}
	RefreshTokens, err := api.DB.GetRefreshToken(context.Background(), user.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var RefreshToken string
	for _, refreshToken := range RefreshTokens {
		if !refreshToken.RevokedAt.Valid {
			RefreshToken = refreshToken.Token
			break
		}
	}
	if RefreshToken == "" {
		RefreshToken, err = api.NewRefreshTokenForUser(user.ID)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, err.Error())
		}
	}
	token, err := auth.MakeJWT(user.ID, api.Secret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
	}
	respondWithJSON(w, http.StatusOK, LoginResponse{User: user, Token: token, RefreshToken: RefreshToken})
}

func (api *API) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	RefreshToken, err := auth.GetKey(r.Header, "Bearer")
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing refresh token")
		return
	}
	TokenInfo, err := api.DB.GetUserFromRefreshToken(context.Background(), RefreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "invalid refresh token")
		return
	}
	if time.Now().After(TokenInfo.ExpiresAt.Time) {
		respondWithError(w, http.StatusUnauthorized, "refresh token expired")
		return
	}
	if TokenInfo.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "refresh token revoked")
		return
	}
	newToken, err := auth.MakeJWT(TokenInfo.UserID, api.Secret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "cannot generate new token")
		return
	}
	respondWithJSON(w, http.StatusOK, struct {
		Token string `json:"token"`
	}{Token: newToken})
}

func (api *API) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	RefreshToken, err := auth.GetKey(r.Header, "Bearer")
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	err = api.DB.RevokeToken(context.Background(), RefreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusNoContent, nil)
}

func (api *API) UpdateEmailAndPassHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetKey(r.Header, "Bearer")
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing token")
		return
	}
	userID, err := auth.ValidateJWT(token, api.Secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	decoder := json.NewDecoder(r.Body)
	dat := UpdateUsersRequest{}
	if err = decoder.Decode(&dat); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	if !emailValidation(dat.Email) {
		respondWithError(w, http.StatusBadRequest, "email validation failed")
		return
	}
	hashedPass, err := auth.HashPassword(dat.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed hashing password: "+err.Error())
		return
	}
	err = api.DB.UpdateEmailAndPass(context.Background(), database.UpdateEmailAndPassParams{
		ID:             userID,
		Email:          dat.Email,
		HashedPassword: hashedPass})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error updating: "+err.Error())
	}
	respondWithJSON(w, http.StatusOK, struct {
		Email string `json:"email"`
	}{Email: dat.Email})
}

func (api *API) UpgradeUserHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetKey(r.Header, "ApiKey")
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "missing token")
		return
	}
	if token != api.SecretPayment {
		respondWithError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	decoder := json.NewDecoder(r.Body)
	dat := UpgradeRequest{}
	if err := decoder.Decode(&dat); err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.Body.Close()
	if dat.Event != "user.upgraded" {
		respondWithError(w, http.StatusBadRequest, "invalid event")
		return
	}
	err = api.DB.UpgradePrem(context.Background(), dat.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Cannot upgrade user: "+err.Error())
		return
	}
	respondWithJSON(w, http.StatusNoContent, nil)
}
