package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"go-jwt-rest-api/models"
	"go-jwt-rest-api/utils"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Controller struct{} // this is shared between all package controllers

func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User

		json.NewDecoder(r.Body).Decode(&user)
		spew.Dump(user)

		if user.Email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Email is missing.") // 400
			return
		}

		if user.Password == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Password is missing.")
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
			utils.RespondWithError(w, http.StatusInternalServerError, "Server error.")
		}

		// since we are returning the user obj, we don't want to show Password
		user.Password = ""
		w.Header().Set("Content-Type", "application/json")
		utils.ResponseJSON(w, user)
	}
}

func (c Controller) Login(db *sql.DB) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var jwt models.JWT

		json.NewDecoder(r.Body).Decode(&user)
		if user.Email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Email is missing.")
			return
		}

		if user.Password == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Password is missing.")
			return
		}

		enteredPassword := user.Password

		row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
		err := row.Scan(&user.ID, &user.Email, &user.Password)
		if err != nil {
			if err == sql.ErrNoRows {
				utils.RespondWithError(w, http.StatusBadRequest, "The user does not exist.")
				return
			} else {
				log.Fatal(err)
			}
		}

		hashedPassword := user.Password

		token, err := utils.GenerateToken(user)
		if err != nil {
			log.Fatal(err)
		}

		isValidPassword := utils.ComparePasswords(hashedPassword, []byte(enteredPassword))
		if isValidPassword {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Authorization", token)

			jwt.Token = token
			utils.ResponseJSON(w, jwt)
		} else {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid Password.")
		}
	}
}

func (c Controller) TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
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
				utils.RespondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				utils.RespondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}

		} else {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token.")
			return
		}
	})
}
