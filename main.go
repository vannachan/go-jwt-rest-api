package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"./driver"
	"./models"

	"github.com/davecgh/go-spew/spew"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

// ===================
// HELPER FUNCTIONS
// ===================
func respondWithError(w http.ResponseWriter, status int, message string) {
	var error models.Error
	error.Message = message
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
	return
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func GenerateToken(user models.User) (string, error) {
	var err error
	// jwt = header.payload.secret
	secret := os.Getenv("SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "testProgram",
	})
	// spew.Dump(token)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

// ===========================
// ROUTER FUNCTION HANDLERS
// ===========================
func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User

	json.NewDecoder(r.Body).Decode(&user)
	spew.Dump(user)

	if user.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is missing.") // 400
		return
	}

	if user.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is missing.")
		return
	}

	// adding password hashing in case our db gets compromised
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}

	// db is expecting a string, convert the hash string of bytes to string
	user.Password = string(hash)

	// inser to db
	stmt := "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Server error.")
	}

	// since we are returning the user obj, we don't want to show Password
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var jwt models.JWT

	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is missing.")
		return
	}

	if user.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is missing.")
		return
	}

	enteredPassword := user.Password

	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "The user does not exist.")
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Password.")
		return
	}

	token, err := GenerateToken(user)
	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked.")
	w.Write([]byte("Successfully reached protected endpoint!"))
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				// validate the algo that we are using
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte(os.Getenv("SECRET")), nil
			})

			if error != nil {
				respondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				respondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}

		} else {
			respondWithError(w, http.StatusUnauthorized, "Invalid token.")
			return
		}
	})
}
