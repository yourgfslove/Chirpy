package Api

import (
	"github.com/google/uuid"
	"github.com/yourgfslove/serverStudy/internal/database"
)

type errorResp struct {
	Error string `json:"error"`
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
