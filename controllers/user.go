package controllers

import (
	"database/sql"
	"encoding/json"
	"go-jwt-rest-api/models"
	"go-jwt-rest-api/repository"
	"go-jwt-rest-api/utils"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type Controller struct{} // this is shared between all package controllers

func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User

		json.NewDecoder(r.Body).Decode(&user)
		// spew.Dump(user)

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
		userRepo := repository.UserRepository{}
		user = userRepo.Signup(db, user)
		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Server error.")
		}

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

		userRepo := repository.UserRepository{}
		user, err := userRepo.Login(db, user)
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
