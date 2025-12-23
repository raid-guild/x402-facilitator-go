package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/raid-guild/x402-facilitator-go/types"
)

// Supported is the handler function called by Vercel.
func Supported(w http.ResponseWriter, r *http.Request) {

	// Build the supported response
	response := buildSupportedResponse()

	// Marshal the response to JSON bytes
	responseBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the content type and write the status code
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write the response bytes to the response body
	if _, err := w.Write(responseBytes); err != nil {
		// Header already written so we log the error
		log.Printf("failed to write response: %v", err)
	}
}

// buildSupportedResponse builds the supported response.
func buildSupportedResponse() types.SupportedResponse {
	var v1Kinds []types.SupportedKind
	var v2Kinds []types.SupportedKind

	// Check if the sepolia network is supported
	if rpcURL := os.Getenv("RPC_URL_SEPOLIA"); rpcURL != "" {
		// Add v1 sepolia support
		v1Kinds = append(v1Kinds, types.SupportedKind{
			X402Version: 1,
			Scheme:      "exact",
			Network:     "sepolia",
		})
		// Add v2 sepolia support
		v2Kinds = append(v2Kinds, types.SupportedKind{
			X402Version: 2,
			Scheme:      "exact",
			Network:     "eip155:11155111",
		})
	}

	// Check if the base sepolia network is supported
	if rpcURL := os.Getenv("RPC_URL_BASE_SEPOLIA"); rpcURL != "" {
		// Add v1 base sepolia support
		v1Kinds = append(v1Kinds, types.SupportedKind{
			X402Version: 1,
			Scheme:      "exact",
			Network:     "base-sepolia",
		})
		// Add v2 base sepolia support
		v2Kinds = append(v2Kinds, types.SupportedKind{
			X402Version: 2,
			Scheme:      "exact",
			Network:     "eip155:84532",
		})
	}

	// Combine v1 kinds then v2 kinds
	kinds := make([]types.SupportedKind, 0)
	kinds = append(kinds, v1Kinds...)
	kinds = append(kinds, v2Kinds...)

	// Return the supported response
	return types.SupportedResponse{
		Kinds: kinds,
	}
}
