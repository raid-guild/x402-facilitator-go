package handler

import (
	"net/http"

	"github.com/raid-guild/x402-facilitator-go/json"
)

// Supported is the handler function called by Vercel.
func Supported(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json.SupportedJSON)
}
