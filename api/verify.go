package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/raid-guild/x402-facilitator-go/auth"
	"github.com/raid-guild/x402-facilitator-go/utils"
)

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
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Unmarshal the request body
	var requestBody RequestBody
	err = json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the payment payload
	paymentPayload := PaymentPayload{}
	json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)

	// Unmarshal the payment requirements
	paymentRequirements := PaymentRequirements{}
	json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)

	// Check the payment version
	if requestBody.X402Version == 1 {

		// Check the payment scheme
		if paymentPayload.Scheme == "exact" {

			// Check the payment network
			if paymentPayload.Network == "eip155:11155111" {

				// Verify the payment on Sepolia
				result, err := verifyV1ExactSepolia(paymentPayload, paymentRequirements)
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

				// Marshal the result to JSON
				resultBytes, err := json.Marshal(result)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write the result to the response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write(resultBytes)
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

// RequestBody is the request body.
type RequestBody struct {
	X402Version         int             `json:"x402Version"`
	PaymentPayload      json.RawMessage `json:"paymentPayload"`
	PaymentRequirements json.RawMessage `json:"paymentRequirements"`
}

// PaymentPayload is the payment payload.
type PaymentPayload struct {
	Scheme        string        `json:"scheme"`
	Network       string        `json:"network"`
	Authorization Authorization `json:"authorization"`
	Signature     string        `json:"signature"`
}

// Authorization is the authorization for the payment.
type Authorization struct {
	To          string `json:"to"`
	From        string `json:"from"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// PaymentRequirements is the payment requirements.
type PaymentRequirements struct {
	Amount        string `json:"amount"`
	Recipient     string `json:"recipient"`
	AssetName     string `json:"assetName"`
	AssetVersion  string `json:"assetVersion"`
	AssetContract string `json:"assetContract"`
}

// VerifyResult is the result of the verification.
type VerifyResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

func verifyV1ExactSepolia(p PaymentPayload, r PaymentRequirements) (VerifyResult, error) {

	now := time.Now()

	// Verify the authorization valid after time is in the past
	validAfter, err := time.Parse(time.RFC3339, p.Authorization.ValidAfter)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			errors.New("invalid valid after time"),
			http.StatusBadRequest,
		)
	}
	if !now.After(validAfter) {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization is not valid yet",
		}, nil
	}

	// Verify the authorization valid before time is in the future
	validBefore, err := time.Parse(time.RFC3339, p.Authorization.ValidBefore)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			errors.New("invalid valid before time"),
			http.StatusBadRequest,
		)
	}
	if !now.Before(validBefore) {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization is expired",
		}, nil
	}

	// Verify the authorization value matches the required amount
	if p.Authorization.Value != r.Amount {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization value does not match required amount",
		}, nil
	}

	// Verify the authorization to matches the required recipient
	if p.Authorization.To != r.Recipient {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization to does not match required recipient",
		}, nil
	}

	bigChainID := big.NewInt(11155111) // Sepolia
	hexChainID := math.HexOrDecimal256(*bigChainID)

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
			Name:              r.AssetName,
			Version:           r.AssetVersion,
			ChainId:           &hexChainID,
			VerifyingContract: r.AssetContract,
		},
		Message: apitypes.TypedDataMessage{
			"from":        p.Authorization.From,
			"to":          p.Authorization.To,
			"value":       p.Authorization.Value,
			"validAfter":  p.Authorization.ValidAfter,
			"validBefore": p.Authorization.ValidBefore,
			"nonce":       p.Authorization.Nonce,
		},
	}

	// Parse the signature
	signature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			errors.New("invalid signature"),
			http.StatusBadRequest,
		)
	}

	// Adjust V value (27/28 → 0/1)
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27
	}

	// Compute EIP-712 hash
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to hash domain: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Compute Message hash
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to hash message: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Construct the signature hash
	rawData := []byte("\x19\x01" + string(domainSeparator) + string(typedDataHash))
	sighash := crypto.Keccak256(rawData)

	// Recover public key
	pubkey, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to recover public key: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Unmarshal public key
	recoveredPubkey, err := crypto.UnmarshalPubkey(pubkey)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to unmarshal public key: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Convert public key to address
	sender := crypto.PubkeyToAddress(*recoveredPubkey)

	// Verify the sender matches the authorization from
	if sender != common.HexToAddress(p.Authorization.From) {
		return VerifyResult{
			Valid:  false,
			Reason: "invalid signature",
		}, nil
	}

	// TODO: more verification logic...

	// Return valid with no error
	return VerifyResult{Valid: true}, nil
}
