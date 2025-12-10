package handler

import (
	"errors"
	"net/http"

	"github.com/raid-guild/x402-facilitator-go/auth"
	"github.com/raid-guild/x402-facilitator-go/utils"
)

// Verify is the main function that is called by Vercel.
func Verify(w http.ResponseWriter, r *http.Request) {

	// Authenticate request
	err := auth.Authenticate(r)
	if err != nil {
		var se utils.StatusError
		if errors.As(err, &se) {
			http.Error(w, err.Error(), se.Status())
			return
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

}
