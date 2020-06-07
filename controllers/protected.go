package controllers

import (
	"go-jwt-rest-api/utils"
	"net/http"
)

func (c Controller) ProtectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		utils.ResponseJSON(w, "Successfully reached protected endpoint!")
	}
}
