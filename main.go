package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/yourgfslove/serverStudy/internal/auth"
	"github.com/yourgfslove/serverStudy/internal/database"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type apiconfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	Platform       string
	Secret         string
}

func (cfg *apiconfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type errorResp struct {
	Error string `json:"error"`
}

type CreateUsersRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type AuthUsersRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type UpdateUsersRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	database.User
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type CreateChirpsRequest struct {
	Body   string    `json:"body"`
	UserId uuid.UUID `json:"user_id"`
}

var api apiconfig

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbRL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbRL)
	if err != nil {
		log.Fatal(err)
	}
	DBQueries := database.New(db)
	api = apiconfig{
		fileserverHits: atomic.Int32{},
		DB:             DBQueries,
		Platform:       os.Getenv("PLATFORM"),
		Secret:         os.Getenv("SECRET"),
	}
	serveMux := http.NewServeMux()
	serv := http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}
	serveMux.Handle("/app/assets/logo.png", api.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	serveMux.Handle("/app/", api.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /admin/metrics", metricsHandler)
	serveMux.HandleFunc("POST /admin/reset", resetHandler)
	serveMux.HandleFunc("POST /api/users", apiUsersHandler)
	serveMux.HandleFunc("POST /api/chirps", apichirpsCreateHandler)
	serveMux.HandleFunc("GET /api/chirps", apiGetchirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{ChirpId}", apiGetOnechirpHandler)
	serveMux.HandleFunc("POST /api/login", apiLoginHandler)
	serveMux.HandleFunc("POST /api/refresh", apiRefreshHandler)
	serveMux.HandleFunc("POST /api/revoke", apiRevokeHandler)
	serveMux.HandleFunc("PUT /api/users", apiUpdateEmailAndPassHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{ChirpId}", apiDeleteChirpHandler)
	err = serv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<html>
  		<body>
    		<h1>Welcome, Chirpy Admin</h1>
    		<p>Chirpy has been visited %d times!</p>
  		</body>
	</html>
	`, api.fileserverHits.Load())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	if api.Platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	api.fileserverHits.Store(0)
	err := api.DB.Reset(context.Background())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte("fileserver reset success"))
}

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

func apiUsersHandler(w http.ResponseWriter, r *http.Request) {
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

func emailValidation(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func apichirpsCreateHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	dat := CreateChirpsRequest{}
	if err := decoder.Decode(&dat); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	defer r.Body.Close()

	token, err := auth.GetToken(r.Header)
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

func apiGetchirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := api.DB.GetAllChirps(context.Background())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJSON(w, http.StatusOK, chirps)
}

func apiGetOnechirpHandler(w http.ResponseWriter, r *http.Request) {
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

func apiLoginHandler(w http.ResponseWriter, r *http.Request) {
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
		RefreshToken, err = NewRefreshTokenForUser(user.ID)
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

func apiRefreshHandler(w http.ResponseWriter, r *http.Request) {
	RefreshToken, err := auth.GetToken(r.Header)
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

func apiRevokeHandler(w http.ResponseWriter, r *http.Request) {
	RefreshToken, err := auth.GetToken(r.Header)
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

func apiUpdateEmailAndPassHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetToken(r.Header)
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

func NewRefreshTokenForUser(userID uuid.UUID) (string, error) {
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

func apiDeleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetToken(r.Header)
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
