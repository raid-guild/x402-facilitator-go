package handler

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
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

	// Decode the request body
	var requestBody RequestBody
	err = json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Unmarshal the payment payload
	paymentPayload := PaymentPayload{}
	err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to unmarshal payment payload: %v", err), http.StatusBadRequest)
		return
	}

	// Unmarshal the payment requirements
	paymentRequirements := PaymentRequirements{}
	err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to unmarshal payment requirements: %v", err), http.StatusBadRequest)
		return
	}

	// Check the payment version
	if requestBody.X402Version == 1 {

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
		if paymentPayload.Scheme == "exact" {

			// Check the payment network
			if paymentPayload.Network == "sepolia" {

				// Verify the payment on Sepolia
				result, err := verifyV1ExactSepolia(paymentPayload.Payload, paymentRequirements)
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
	Scheme  string  `json:"scheme"`
	Network string  `json:"network"`
	Payload Payload `json:"payload"`
}

// Payload is the payload for the payment.
type Payload struct {
	Signature     string        `json:"signature"`
	Authorization Authorization `json:"authorization"`
}

// Authorization is the authorization for the payment.
type Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       int64  `json:"value"`
	ValidAfter  int64  `json:"validAfter"`
	ValidBefore int64  `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// PaymentRequirements is the payment requirements.
type PaymentRequirements struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	MaxAmountRequired int64  `json:"maxAmountRequired"`
	Asset             string `json:"asset"`
	PayTo             string `json:"payTo"`
	Extra             Extra  `json:"extra"`
}

// Extra is the extra for the payment.
type Extra struct {
	Name    string `json:"assetName"`
	Version string `json:"assetVersion"`
}

// VerifyResult is the result of the verification.
type VerifyResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

func verifyV1ExactSepolia(p Payload, r PaymentRequirements) (VerifyResult, error) {

	now := time.Now()

	// Verify the authorization valid after time is in the past
	validAfter := time.Unix(p.Authorization.ValidAfter, 0)
	if !now.After(validAfter) {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization is not valid yet",
		}, nil
	}

	// Verify the authorization valid before time is in the future
	validBefore := time.Unix(p.Authorization.ValidBefore, 0)
	if !now.Before(validBefore) {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization is expired",
		}, nil
	}

	// Verify the authorization value matches the required amount
	if p.Authorization.Value < r.MaxAmountRequired {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization value is less than the required maximum amount",
		}, nil
	}

	// Verify the authorization to matches the required pay to address
	if p.Authorization.To != r.PayTo {
		return VerifyResult{
			Valid:  false,
			Reason: "authorization to does not match required pay to address",
		}, nil
	}

	// Convert the chain ID to hex or decimal
	bigChainID := big.NewInt(11155111) // Sepolia
	hexChainID := math.HexOrDecimal256(*bigChainID)

	// Decode the nonce from hex to bytes
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(p.Authorization.Nonce, "0x"))
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to decode nonce: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Validate that the nonce is exactly 32 bytes (bytes32)
	if len(nonceBytes) != 32 {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("nonce must be exactly 32 bytes, got %d bytes", len(nonceBytes)),
			http.StatusBadRequest,
		)
	}

	// Convert the nonce bytes to a 32 byte array
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

	// Compute the EIP-712 hash
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to hash domain: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Compute the Message hash
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

	// Parse the payload signature
	signature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			errors.New("invalid signature"),
			http.StatusBadRequest,
		)
	}

	// Validate that the signature is exactly 65 bytes (32 bytes r + 32 bytes s + 1 byte v)
	if len(signature) != 65 {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("signature must be exactly 65 bytes, got %d bytes", len(signature)),
			http.StatusBadRequest,
		)
	}

	// Convert the V value if necessary (27/28 → 0/1)
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27
	}

	// Recover the public key
	pubkey, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to recover public key: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Unmarshal the public key
	recoveredPubkey, err := crypto.UnmarshalPubkey(pubkey)
	if err != nil {
		return VerifyResult{}, utils.NewStatusError(
			fmt.Errorf("failed to unmarshal public key: %v", err),
			http.StatusInternalServerError,
		)
	}

	// Convert the public key to an address
	sender := crypto.PubkeyToAddress(*recoveredPubkey)

	// Verify the sender matches the authorization from
	if sender != common.HexToAddress(p.Authorization.From) {
		return VerifyResult{
			Valid:  false,
			Reason: "invalid signature",
		}, nil
	}

	// Return valid with no error
	return VerifyResult{Valid: true}, nil
}
