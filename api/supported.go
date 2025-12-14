package handler

import (
	"log"
	"net/http"

	"github.com/raid-guild/x402-facilitator-go/json"
)

// Supported is the handler function called by Vercel.
func Supported(w http.ResponseWriter, r *http.Request) {

	// Set the content type and write the status code
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write the supported JSON to the response body
	if _, err := w.Write(json.SupportedJSON); err != nil {
		// Header already written so we log the error
		log.Printf("failed to write response: %v", err)
	}

}
