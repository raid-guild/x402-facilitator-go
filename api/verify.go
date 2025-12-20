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

		// Unmarshal the payment payload
		var paymentPayload v1.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements v1.PaymentRequirements
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
		if paymentRequirements.Scheme == v1.SchemeExact {

			// Set the verify exact parameters
			exactParams := core.VerifyExactParams{
				Signature:                paymentPayload.Payload.Signature,
				AuthorizationValidAfter:  paymentPayload.Payload.Authorization.ValidAfter,
				AuthorizationValidBefore: paymentPayload.Payload.Authorization.ValidBefore,
				AuthorizationValue:       paymentPayload.Payload.Authorization.Value,
				AuthorizationFrom:        paymentPayload.Payload.Authorization.From,
				AuthorizationTo:          paymentPayload.Payload.Authorization.To,
				AuthorizationNonce:       paymentPayload.Payload.Authorization.Nonce,
				Asset:                    paymentRequirements.Asset,
				PayTo:                    paymentRequirements.PayTo,
				MaxAmountRequired:        paymentRequirements.MaxAmountRequired,
				MaxTimeoutSeconds:        paymentRequirements.MaxTimeoutSeconds,
				ExtraName:                paymentRequirements.Extra.Name,
				ExtraVersion:             paymentRequirements.Extra.Version,
				ExtraGasLimit:            paymentRequirements.Extra.GasLimit,
			}

			// Handle requests for sepolia network
			if paymentRequirements.Network == v1.NetworkSepolia {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 11155111,
					RPCURL:  os.Getenv("RPC_URL_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Sepolia test network
				response, err := core.VerifyExact(cfg, exactParams)
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
			if paymentRequirements.Network == v1.NetworkBaseSepolia {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 84532,
					RPCURL:  os.Getenv("RPC_URL_BASE_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Base Sepolia test network
				response, err := core.VerifyExact(cfg, exactParams)
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

		// Unmarshal the payment payload
		var paymentPayload v2.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements v2.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidPaymentRequirements)
			return
		}

		// Check the payment payload and requirements scheme
		if paymentPayload.Accepted.Scheme != paymentRequirements.Scheme {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidSchemeMismatch)
			return
		}

		// Check the payment payload and requirements network
		if paymentPayload.Accepted.Network != paymentRequirements.Network {
			// Write http ok response with error reason and then exit handler
			writeVerifyResponseWithInvalidReason(w, types.InvalidReasonInvalidNetworkMismatch)
			return
		}

		// Handle requests for exact scheme
		if paymentRequirements.Scheme == v2.SchemeExact {

			// Set the verify exact parameters
			exactParams := core.VerifyExactParams{
				Signature:                paymentPayload.Payload.Signature,
				AuthorizationFrom:        paymentPayload.Payload.Authorization.From,
				AuthorizationTo:          paymentPayload.Payload.Authorization.To,
				AuthorizationValue:       paymentPayload.Payload.Authorization.Value,
				AuthorizationValidAfter:  paymentPayload.Payload.Authorization.ValidAfter,
				AuthorizationValidBefore: paymentPayload.Payload.Authorization.ValidBefore,
				AuthorizationNonce:       paymentPayload.Payload.Authorization.Nonce,
				Asset:                    paymentRequirements.Asset,
				PayTo:                    paymentRequirements.PayTo,
				MaxAmountRequired:        paymentRequirements.Amount,
				MaxTimeoutSeconds:        paymentRequirements.MaxTimeoutSeconds,
				ExtraName:                paymentRequirements.Extra.Name,
				ExtraVersion:             paymentRequirements.Extra.Version,
				ExtraGasLimit:            paymentRequirements.Extra.GasLimit,
			}

			// Handle requests for sepolia network
			if paymentRequirements.Network == v2.NetworkSepolia {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 11155111,
					RPCURL:  os.Getenv("RPC_URL_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Sepolia test network
				response, err := core.VerifyExact(cfg, exactParams)
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
			if paymentRequirements.Network == v2.NetworkBaseSepolia {

				// Set the verify exact configuration
				cfg := core.VerifyExactConfig{
					ChainID: 84532,
					RPCURL:  os.Getenv("RPC_URL_BASE_SEPOLIA"),
				}

				// Verify the payment that will be settled on the Base Sepolia test network
				response, err := core.VerifyExact(cfg, exactParams)
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
