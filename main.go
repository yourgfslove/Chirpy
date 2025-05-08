package main

import (
	"database/sql"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/yourgfslove/serverStudy/internal/Api"
	"github.com/yourgfslove/serverStudy/internal/database"
	"log"
	"net/http"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	DBQueries := database.New(db)
	api := Api.NewAPI(DBQueries, os.Getenv("PLATFORM"), os.Getenv("SECRET"), os.Getenv("PAYMENT_APIKEY"))

	serv := http.Server{
		Addr:    ":8080",
		Handler: api.Routes(),
	}

	err = serv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
