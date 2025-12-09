package handler

import (
	"fmt"
	"net/http"
)

// Handler is the main function that is called by Vercel.
func Handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello x402 Facilitator</h1>")
}
