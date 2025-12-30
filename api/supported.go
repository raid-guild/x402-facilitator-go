package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/raid-guild/x402-facilitator-go/types"
	v1 "github.com/raid-guild/x402-facilitator-go/types/v1"
	v2 "github.com/raid-guild/x402-facilitator-go/types/v2"
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

	// Check if the ethereum network is supported
	if rpcURL := os.Getenv("RPC_URL_ETHEREUM"); rpcURL != "" {
		// Add v1 ethereum support
		v1Kinds = append(v1Kinds, types.SupportedKind{
			X402Version: int(types.X402Version1),
			Scheme:      string(v1.SchemeExact),
			Network:     string(v1.NetworkEthereum),
		})
		// Add v2 ethereum support
		v2Kinds = append(v2Kinds, types.SupportedKind{
			X402Version: int(types.X402Version2),
			Scheme:      string(v2.SchemeExact),
			Network:     string(v2.NetworkEthereum),
		})
	}

	// Check if the base network is supported
	if rpcURL := os.Getenv("RPC_URL_BASE"); rpcURL != "" {
		// Add v1 base support
		v1Kinds = append(v1Kinds, types.SupportedKind{
			X402Version: int(types.X402Version1),
			Scheme:      string(v1.SchemeExact),
			Network:     string(v1.NetworkBase),
		})
		// Add v2 base support
		v2Kinds = append(v2Kinds, types.SupportedKind{
			X402Version: int(types.X402Version2),
			Scheme:      string(v2.SchemeExact),
			Network:     string(v2.NetworkBase),
		})
	}

	// Check if the sepolia network is supported
	if rpcURL := os.Getenv("RPC_URL_SEPOLIA"); rpcURL != "" {
		// Add v1 sepolia support
		v1Kinds = append(v1Kinds, types.SupportedKind{
			X402Version: int(types.X402Version1),
			Scheme:      string(v1.SchemeExact),
			Network:     string(v1.NetworkSepolia),
		})
		// Add v2 sepolia support
		v2Kinds = append(v2Kinds, types.SupportedKind{
			X402Version: int(types.X402Version2),
			Scheme:      string(v2.SchemeExact),
			Network:     string(v2.NetworkSepolia),
		})
	}

	// Check if the base sepolia network is supported
	if rpcURL := os.Getenv("RPC_URL_BASE_SEPOLIA"); rpcURL != "" {
		// Add v1 base sepolia support
		v1Kinds = append(v1Kinds, types.SupportedKind{
			X402Version: int(types.X402Version1),
			Scheme:      string(v1.SchemeExact),
			Network:     string(v1.NetworkBaseSepolia),
		})
		// Add v2 base sepolia support
		v2Kinds = append(v2Kinds, types.SupportedKind{
			X402Version: int(types.X402Version2),
			Scheme:      string(v2.SchemeExact),
			Network:     string(v2.NetworkBaseSepolia),
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
