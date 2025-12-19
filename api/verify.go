package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/raid-guild/x402-facilitator-go/auth"
	"github.com/raid-guild/x402-facilitator-go/core"
	"github.com/raid-guild/x402-facilitator-go/types"
	"github.com/raid-guild/x402-facilitator-go/utils"
)

// Verify is the handler function called by Vercel.
func Verify(w http.ResponseWriter, r *http.Request) {

	// Authenticate request
	err := auth.Authenticate(r)
	if err != nil {
		var se utils.StatusError
		if errors.As(err, &se) {
			// Write http error response and then exit handler
			http.Error(w, err.Error(), se.Status())
			return
		} else {
			// Write http error response and then exit handler
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Decode the request body
	var requestBody types.RequestBody
	err = json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		// Write http error response and then exit handler
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Handle requests for x402 Version 1
	if requestBody.X402Version == types.X402Version1 {

		// NOTE: The types for payment payload and payment requirements are the same for v1 and v2.
		// This will change in the future but for now we perform the same checks for both versions.

		// Unmarshal the payment payload
		var paymentPayload types.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements types.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentRequirements)
			return
		}

		// Check the payment payload and requirements scheme
		if paymentPayload.Scheme != paymentRequirements.Scheme {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidSchemeMismatch)
			return
		}

		// Check the payment payload and requirements network
		if paymentPayload.Network != paymentRequirements.Network {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidNetworkMismatch)
			return
		}

		// Handle requests for exact scheme
		if paymentPayload.Scheme == types.SchemeExact {

			// Handle requests for sepolia network
			if paymentPayload.Network == types.NetworkSepolia {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 11155111,
					RPCURL:  os.Getenv("RPC_URL_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Sepolia test network
				response, err := core.VerifyExact(cfg, paymentPayload.Payload, paymentRequirements)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeVerifyResponse(w, response)
				return
			}

			// Handle requests for base sepolia network
			if paymentPayload.Network == types.NetworkBaseSepolia {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 84532,
					RPCURL:  os.Getenv("RPC_URL_BASE_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Sepolia test network
				response, err := core.VerifyExact(cfg, paymentPayload.Payload, paymentRequirements)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeVerifyResponse(w, response)
				return
			}

			// TODO: Add support for other v1 networks

			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidNetwork)
			return
		}

		// TODO: Add support for other v1 schemes

		// Write http ok response with error reason and then exit handler
		writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidScheme)
		return
	}

	// Handle requests for x402 Version 2
	if requestBody.X402Version == types.X402Version2 {

		// NOTE: The types for payment payload and payment requirements are the same for v1 and v2.
		// This will change in the future but for now we perform the same checks for both versions.

		// Unmarshal the payment payload
		var paymentPayload types.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements types.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentRequirements)
			return
		}

		// Check the payment payload and requirements scheme
		if paymentPayload.Scheme != paymentRequirements.Scheme {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidSchemeMismatch)
			return
		}

		// Check the payment payload and requirements network
		if paymentPayload.Network != paymentRequirements.Network {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidNetworkMismatch)
			return
		}

		// Handle requests for exact scheme
		if paymentPayload.Scheme == types.SchemeExact {

			// Handle requests for sepolia network
			if paymentPayload.Network == types.NetworkSepoliaV2 {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 11155111,
					RPCURL:  os.Getenv("RPC_URL_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Sepolia test network
				response, err := core.VerifyExact(cfg, paymentPayload.Payload, paymentRequirements)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeVerifyResponse(w, response)
				return
			}

			// Handle requests for base sepolia network
			if paymentPayload.Network == types.NetworkBaseSepoliaV2 {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 84532,
					RPCURL:  os.Getenv("RPC_URL_BASE_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Sepolia test network
				response, err := core.VerifyExact(cfg, paymentPayload.Payload, paymentRequirements)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeVerifyResponse(w, response)
				return
			}

			// TODO: Add support for other v2 networks

			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidNetwork)
			return
		}

		// TODO: Add support for other v2 schemes

		// Write http ok response with error reason and then exit handler
		writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidScheme)
		return
	}

	// TODO: Add support for other x402 versions

	// Write http ok response with error reason and then exit handler
	writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidX402Version)
}

// writeVerifyResponse writes the verify response to the response body.
func writeVerifyResponse(w http.ResponseWriter, response types.VerifyResponse) {

	// Marshal the response into JSON bytes
	responseBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the content type and write the status code
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write the response bytes to the response body
	_, err = w.Write(responseBytes)
	if err != nil {
		// Header already written so we log the error
		log.Printf("failed to write response: %v", err)
	}
}

// writeVerifyResponseWithInvalidReason writes the verify response to the response body.
func writeVerifyResponseWithInvalidReason(w http.ResponseWriter, invalidReason types.InvalidReason) {

	// Write the verify response with the invalid reason
	writeVerifyResponse(w, types.VerifyResponse{
		IsValid:       false,
		InvalidReason: invalidReason,
	})
}
