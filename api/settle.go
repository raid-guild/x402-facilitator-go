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
	v1 "github.com/raid-guild/x402-facilitator-go/types/v1"
	v2 "github.com/raid-guild/x402-facilitator-go/types/v2"
	"github.com/raid-guild/x402-facilitator-go/utils"
)

// Settle is the handler function called by Vercel.
func Settle(w http.ResponseWriter, r *http.Request) {

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

		// Unmarshal the payment payload
		var paymentPayload v1.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements v1.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidPaymentRequirements)
			return
		}

		// Handle requests for exact scheme
		if paymentRequirements.Scheme == v1.SchemeExact {

			// Set the settle exact parameters
			exactParams := core.SettleExactParams{
				Signature:                paymentPayload.Payload.Signature,
				AuthorizationFrom:        paymentPayload.Payload.Authorization.From,
				AuthorizationTo:          paymentPayload.Payload.Authorization.To,
				AuthorizationValue:       paymentPayload.Payload.Authorization.Value,
				AuthorizationValidAfter:  paymentPayload.Payload.Authorization.ValidAfter,
				AuthorizationValidBefore: paymentPayload.Payload.Authorization.ValidBefore,
				AuthorizationNonce:       paymentPayload.Payload.Authorization.Nonce,
				Asset:                    paymentRequirements.Asset,
				MaxTimeoutSeconds:        paymentRequirements.MaxTimeoutSeconds,
				ExtraGasLimit:            paymentRequirements.Extra.GasLimit,
			}

			// Handle requests for sepolia network
			if paymentRequirements.Network == v1.NetworkSepolia {

				// Set the settle exact configuration
				cfg := core.SettleExactConfig{
					ChainID:    11155111,
					RPCURL:     os.Getenv("RPC_URL_SEPOLIA"),
					PrivateKey: os.Getenv("PRIVATE_KEY"),
				}

				// Settle the payment by sending a transaction on the Sepolia test network
				response, err := core.SettleExact(cfg, exactParams)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeSettleResponse(w, response)
				return
			}

			// Handle requests for base sepolia network
			if paymentRequirements.Network == v1.NetworkBaseSepolia {

				// Set the settle exact configuration
				cfg := core.SettleExactConfig{
					ChainID:    84532,
					RPCURL:     os.Getenv("RPC_URL_BASE_SEPOLIA"),
					PrivateKey: os.Getenv("PRIVATE_KEY"),
				}

				// Settle the payment by sending a transaction on the Base Sepolia test network
				response, err := core.SettleExact(cfg, exactParams)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeSettleResponse(w, response)
				return
			}

			// TODO: Add support for other v1 networks

			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidNetwork)
			return
		}

		// TODO: Add support for other v1 schemes

		// Write http ok response with error reason and then exit handler
		writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidScheme)
		return
	}

	// Handle requests for x402 Version 2
	if requestBody.X402Version == types.X402Version2 {

		// Unmarshal the payment payload
		var paymentPayload v2.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements v2.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidPaymentRequirements)
			return
		}

		// Handle requests for exact scheme
		if paymentRequirements.Scheme == v2.SchemeExact {

			// Set the settle exact parameters
			exactParams := core.SettleExactParams{
				Signature:                paymentPayload.Payload.Signature,
				AuthorizationFrom:        paymentPayload.Payload.Authorization.From,
				AuthorizationTo:          paymentPayload.Payload.Authorization.To,
				AuthorizationValue:       paymentPayload.Payload.Authorization.Value,
				AuthorizationValidAfter:  paymentPayload.Payload.Authorization.ValidAfter,
				AuthorizationValidBefore: paymentPayload.Payload.Authorization.ValidBefore,
				AuthorizationNonce:       paymentPayload.Payload.Authorization.Nonce,
				Asset:                    paymentRequirements.Asset,
				MaxTimeoutSeconds:        paymentRequirements.MaxTimeoutSeconds,
				ExtraGasLimit:            paymentRequirements.Extra.GasLimit,
			}

			// Handle requests for sepolia network
			if paymentRequirements.Network == v2.NetworkSepolia {

				// Set the settle exact configuration
				cfg := core.SettleExactConfig{
					ChainID:    11155111,
					RPCURL:     os.Getenv("RPC_URL_SEPOLIA"),
					PrivateKey: os.Getenv("PRIVATE_KEY"),
				}

				// Settle the payment by sending a transaction on the Sepolia test network
				response, err := core.SettleExact(cfg, exactParams)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeSettleResponse(w, response)
				return
			}

			// Handle requests for base sepolia network
			if paymentRequirements.Network == v2.NetworkBaseSepolia {

				// Set the settle exact configuration
				cfg := core.SettleExactConfig{
					ChainID:    84532,
					RPCURL:     os.Getenv("RPC_URL_BASE_SEPOLIA"),
					PrivateKey: os.Getenv("PRIVATE_KEY"),
				}

				// Settle the payment by sending a transaction on the Base Sepolia test network
				response, err := core.SettleExact(cfg, exactParams)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeSettleResponse(w, response)
				return
			}

			// TODO: Add support for other v2 networks

			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidNetwork)
			return
		}

		// TODO: Add support for other v2 schemes

		// Write http ok response with error reason and then exit handler
		writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidScheme)
		return
	}

	// TODO: Add support for other x402 versions

	// Write http ok response with error reason and then exit handler
	writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidX402Version)
}

// writeSettleResponse writes the settle response to the response body.
func writeSettleResponse(w http.ResponseWriter, response types.SettleResponse) {

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

// writeSettleResponseWithErrorReason writes the settle response to the response body.
func writeSettleResponseWithErrorReason(w http.ResponseWriter, errorReason types.ErrorReason) {

	// Write the settle response with the error reason
	writeSettleResponse(w, types.SettleResponse{
		Success:     false,
		ErrorReason: errorReason,
	})
}
