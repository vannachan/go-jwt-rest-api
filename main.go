package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {
	pgUrl, err := pq.ParseURL("postgres://csfaqqxs:WrG1SYnqkvZfh7r5HNeVrg-9kPjUiB1Y@ruby.db.elephantsql.com:5432/csfaqqxs")
	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

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
func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
	return
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func GenerateToken(user User) (string, error) {
	var err error
	// jwt = header.payload.secret
	secret := "secret"

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
	var user User
	var error Error

	json.NewDecoder(r.Body).Decode(&user)
	spew.Dump(user)

	if user.Email == "" {
		error.Message = "Email is missing."
		respondWithError(w, http.StatusBadRequest, error) // 400
	}

	if user.Password == "" {
		error.Message = "Password is missing."
		respondWithError(w, http.StatusBadRequest, error) // 400
	}

	// adding password hashing in case our db gets compromised
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}

	// db is expecting a string, convert the hash string of bytes to string
	user.Password = string(hash)

	// inser to db
	stmt := "INSER INTO users (email, password) VALUES ($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		error.Message = "Server error."
		respondWithError(w, http.StatusInternalServerError, error)
	}

	// since we are returning the user obj, we don't want to show Password
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
	var error Error

	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		error.Message = "Email is missing."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "Password is missing."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	enteredPassword := user.Password

	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist."
			respondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
	if err != nil {
		error.Message = "Invalid Password."
		respondWithError(w, http.StatusUnauthorized, error)
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
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObj Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				// validate the algo that we are using
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte("secret"), nil
			})

			if error != nil {
				errorObj.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObj)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObj.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObj)
				return
			}

		} else {
			errorObj.Message = "Invalid token."
			respondWithError(w, http.StatusUnauthorized, errorObj)
			return
		}
	})
}
