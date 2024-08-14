package main

import (
	"errors"
	"fmt"
	"net/http"
)

func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	// read the json request body
	err := app.readJSON(w, r, &requestPayload)
	// check if the request is valid
	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	// check if the user exists in the database
	// if the user exists, send the user's details back
	// if the user does not exist, send an error message
	user, err := app.Models.User.GetByEmail(requestPayload.Email)
	// check if the user exists
	if err != nil {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := user.PasswordMatches(requestPayload.Password)
	if err != nil || !valid {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: fmt.Sprintf("Authenticated in user %s", user.Email),
		Data:    user,
	}

	// send the user's details back
	_ = app.writeJSON(w, http.StatusAccepted, payload)
}
