package Api

import (
	"github.com/yourgfslove/serverStudy/internal/database"
	"net/http"
)

type API struct {
	DB            *database.Queries
	Platform      string
	Secret        string
	SecretPayment string
}

func NewAPI(db *database.Queries, Platform string, Secret string, SecretPayment string) *API {
	return &API{DB: db, Platform: Platform, Secret: Secret, SecretPayment: SecretPayment}
}

func (api *API) Routes() *http.ServeMux {
	serveMux := http.NewServeMux()
	serveMux.Handle("/app/assets/logo.png", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	serveMux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	serveMux.HandleFunc("POST /admin/reset", api.ResetHandler)
	serveMux.HandleFunc("POST /api/users", api.UsersHandler)
	serveMux.HandleFunc("POST /api/chirps", api.ChirpsCreateHandler)
	serveMux.HandleFunc("GET /api/chirps", api.GetChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{ChirpId}", api.GetChirpHandler)
	serveMux.HandleFunc("POST /api/login", api.LoginHandler)
	serveMux.HandleFunc("POST /api/refresh", api.RefreshHandler)
	serveMux.HandleFunc("POST /api/revoke", api.RevokeHandler)
	serveMux.HandleFunc("PUT /api/users", api.UpdateEmailAndPassHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{ChirpId}", api.DeleteChirpHandler)
	serveMux.HandleFunc("POST /api/paymentMethod/webhooks", api.UpgradeUserHandler)
	return serveMux
}
