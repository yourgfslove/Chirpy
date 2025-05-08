package Api

import "github.com/google/uuid"

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

type UpgradeRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	} `json:"data"`
}
