package handler

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/raid-guild/x402-facilitator-go/auth"
	"github.com/raid-guild/x402-facilitator-go/types"
	"github.com/raid-guild/x402-facilitator-go/utils"
)

// VerifyResponse is the response of the verification.
type VerifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason"`
}

// Verify is the handler function called by Vercel.
func Verify(w http.ResponseWriter, r *http.Request) {

	// Authenticate request
	err := auth.Authenticate(r)
	if err != nil {
		var se utils.StatusError
		if errors.As(err, &se) {
			http.Error(w, err.Error(), se.Status())
			return
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Decode the request body
	var requestBody types.RequestBody
	err = json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check the x402 version
	if requestBody.X402Version == types.X402Version1 {

		// Unmarshal the payment payload
		var paymentPayload types.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to unmarshal payment payload: %v", err), http.StatusBadRequest)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements types.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to unmarshal payment requirements: %v", err), http.StatusBadRequest)
			return
		}

		// Check the payment payload and requirements scheme
		if paymentPayload.Scheme != paymentRequirements.Scheme {
			http.Error(w, "payment scheme does not match requirements scheme", http.StatusBadRequest)
			return
		}

		// Check the payment payload and requirements network
		if paymentPayload.Network != paymentRequirements.Network {
			http.Error(w, "payment network does not match requirements network", http.StatusBadRequest)
			return
		}

		// Check the payment scheme
		if paymentPayload.Scheme == types.SchemeExact {

			// Check the payment network
			if paymentPayload.Network == "sepolia" {

				// Verify the payment that will be settled on the Sepolia test network
				response := verifyV1ExactSepolia(paymentPayload.Payload, paymentRequirements)

				// Marshal the response to JSON
				responseBytes, err := json.Marshal(response)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Set the content type and write the status code
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)

				// Write the response to the response body
				_, err = w.Write(responseBytes)
				if err != nil {
					// Header already written so we log the error
					log.Printf("failed to write response: %v", err)
				}

				return
			}

			// TODO: Add support for other networks

			http.Error(w, "Unsupported payment network", http.StatusNotImplemented)
			return
		}

		// TODO: Add support for other schemes

		http.Error(w, "Unsupported payment scheme", http.StatusNotImplemented)
		return
	}

	// TODO: Add support for other versions

	http.Error(w, "Unsupported x402 version", http.StatusNotImplemented)
}

func verifyV1ExactSepolia(p types.Payload, r types.PaymentRequirements) VerifyResponse {

	now := time.Now()

	// Verify the authorization time window is valid
	if p.Authorization.ValidAfter >= p.Authorization.ValidBefore {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization time window",
		}
	}

	// Verify the authorization valid after time is in the past
	validAfter := time.Unix(p.Authorization.ValidAfter, 0)
	if !now.After(validAfter) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization valid after",
		}
	}

	// Verify the authorization valid before time is in the future
	validBefore := time.Unix(p.Authorization.ValidBefore, 0)
	if !now.Before(validBefore) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization valid before",
		}
	}

	// Verify the authorization value is non-negative
	if p.Authorization.Value < 0 {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization value negative",
		}
	}

	// Verify the authorization value does not exceed the maximum allowed amount
	if p.Authorization.Value > r.MaxAmountRequired {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization value greater than max amount required",
		}
	}

	// Verify the requirements max timeout seconds is positive
	if r.MaxTimeoutSeconds <= 0 {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "requirements max timeout seconds",
		}
	}

	// Verify authorization from is a valid address
	if !common.IsHexAddress(p.Authorization.From) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization from",
		}
	}

	// Verify authorization to is a valid address
	if !common.IsHexAddress(p.Authorization.To) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization to",
		}
	}

	// Verify requirements pay to is a valid address
	if !common.IsHexAddress(r.PayTo) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "requirements pay to",
		}
	}

	// Verify the authorization to address matches the required pay to address
	if common.HexToAddress(p.Authorization.To) != common.HexToAddress(r.PayTo) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "authorization to address does not match pay to address",
		}
	}

	// Decode the nonce from hex to bytes
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(p.Authorization.Nonce, "0x"))
	if err != nil {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("authorization nonce: %v", err),
		}
	}

	// Validate the nonce is exactly 32 bytes
	if len(nonceBytes) != 32 {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("authorization nonce length: %v", len(nonceBytes)),
		}
	}

	// Verify requirements asset is a valid address
	if !common.IsHexAddress(r.Asset) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "requirements asset",
		}
	}

	// Verify requirements extra name is not empty
	if r.Extra.Name == "" {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "requirements extra name",
		}
	}

	// Verify requirements extra version is not empty
	if r.Extra.Version == "" {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "requirements extra version",
		}
	}

	// Convert the chain ID to hex or decimal
	bigChainID := big.NewInt(11155111) // Sepolia
	hexChainID := math.HexOrDecimal256(*bigChainID)

	// Convert the nonce bytes to 32 byte slice
	var nonce [32]byte
	copy(nonce[:], nonceBytes)

	// Construct the typed data
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{
					Name: "name",
					Type: "string",
				},
				{
					Name: "version",
					Type: "string",
				},
				{
					Name: "chainId",
					Type: "uint256",
				},
				{
					Name: "verifyingContract",
					Type: "address",
				},
			},
			"TransferWithAuthorization": []apitypes.Type{
				{
					Name: "from",
					Type: "address",
				},
				{
					Name: "to",
					Type: "address",
				},
				{
					Name: "value",
					Type: "uint256",
				},
				{
					Name: "validAfter",
					Type: "uint256",
				},
				{
					Name: "validBefore",
					Type: "uint256",
				},
				{
					Name: "nonce",
					Type: "bytes32",
				},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              r.Extra.Name,
			Version:           r.Extra.Version,
			ChainId:           &hexChainID,
			VerifyingContract: r.Asset,
		},
		Message: apitypes.TypedDataMessage{
			"from":        p.Authorization.From,
			"to":          p.Authorization.To,
			"value":       big.NewInt(p.Authorization.Value),
			"validAfter":  big.NewInt(p.Authorization.ValidAfter),
			"validBefore": big.NewInt(p.Authorization.ValidBefore),
			"nonce":       nonce,
		},
	}

	// Compute the domain hash
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("hashed domain: %v", err),
		}
	}

	// Compute the message hash
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("hashed message: %v", err),
		}
	}

	// Construct the signature hash
	rawData := append(append([]byte("\x19\x01"), domainSeparator...), typedDataHash...)
	sighash := crypto.Keccak256(rawData)

	// Parse the payload signature
	signature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("signature: %v", err),
		}
	}

	// Verify the signature is exactly 65 bytes (32 bytes r + 32 bytes s + 1 byte v)
	if len(signature) != 65 {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("signature length: %v", len(signature)),
		}
	}

	// Convert the V value of the signature if necessary (27/28 → 0/1)
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27
	}

	// Recover the public key
	pubkey, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("signature hash: %v", err),
		}
	}

	// Check the public key format
	var pubkeyBytes []byte
	if len(pubkey) == 64 {
		// Prepend 0x04 for uncompressed public key format
		pubkeyBytes = append([]byte{0x04}, pubkey...)
	} else if len(pubkey) == 65 {
		// Already in correct format
		pubkeyBytes = pubkey
	} else {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("signature pubkey length: %v", len(pubkey)),
		}
	}

	// Unmarshal the public key
	recoveredPubkey, err := crypto.UnmarshalPubkey(pubkeyBytes)
	if err != nil {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: fmt.Sprintf("signature pubkey: %v", err),
		}
	}

	// Convert the public key to an address
	sender := crypto.PubkeyToAddress(*recoveredPubkey)

	// Verify the sender matches the authorization from
	if sender != common.HexToAddress(p.Authorization.From) {
		return VerifyResponse{
			IsValid:       false,
			InvalidReason: "signature sender does not match authorization from address",
		}
	}

	// Return verify response valid
	return VerifyResponse{IsValid: true}
}
