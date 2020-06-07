package main

import (
	"database/sql"
	"log"
	"net/http"

	"go-jwt-rest-api/controllers"
	"go-jwt-rest-api/driver"
	"go-jwt-rest-api/utils"

	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	controller := controllers.Controller{}

	router := mux.NewRouter()
	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", utils.TokenVerifyMiddleWare(controller.ProtectedEndpoint())).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}
