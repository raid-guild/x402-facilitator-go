package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/raid-guild/x402-facilitator-go/auth"
	"github.com/raid-guild/x402-facilitator-go/clients"
	"github.com/raid-guild/x402-facilitator-go/types"
	"github.com/raid-guild/x402-facilitator-go/utils"
)

// SettleResponse is the response of the settle operation.
type SettleResponse struct {
	Success     bool              `json:"success"`
	Transaction string            `json:"transaction,omitempty"`
	ErrorReason types.ErrorReason `json:"errorReason,omitempty"`
}

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

	// Check the x402 version
	if requestBody.X402Version == types.X402Version1 {

		// Unmarshal the payment payload
		var paymentPayload types.PaymentPayload
		err = json.Unmarshal(requestBody.PaymentPayload, &paymentPayload)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidPaymentPayload)
			return
		}

		// Unmarshal the payment requirements
		var paymentRequirements types.PaymentRequirements
		err = json.Unmarshal(requestBody.PaymentRequirements, &paymentRequirements)
		if err != nil {
			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidPaymentRequirements)
			return
		}

		// Check the payment scheme
		if paymentPayload.Scheme == types.SchemeExact {

			// Check the payment network
			if paymentPayload.Network == types.NetworkSepolia {

				// Settle the payment by sending a transaction on the Sepolia test network
				response, err := settleV1ExactSepolia(paymentPayload.Payload, paymentRequirements)
				if err != nil {
					// Write http error response and then exit handler
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Write http ok response and then exit handler
				writeSettleResponse(w, response)
				return
			}

			// TODO: Add support for other networks

			// Write http ok response with error reason and then exit handler
			writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidNetwork)
			return
		}

		// TODO: Add support for other schemes

		// Write http ok response with error reason and then exit handler
		writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidScheme)
		return
	}

	// TODO: Add support for other versions

	// Write http ok response with error reason and then exit handler
	writeSettleResponseWithErrorReason(w, types.ErrorReasonInvalidX402Version)
}

// writeSettleResponse writes the settle response to the response body.
func writeSettleResponse(w http.ResponseWriter, response SettleResponse) {

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
	writeSettleResponse(w, SettleResponse{
		Success:     false,
		ErrorReason: errorReason,
	})
}

// settleV1ExactSepolia settles the payment on the Sepolia test network.
func settleV1ExactSepolia(p types.Payload, r types.PaymentRequirements) (SettleResponse, error) {

	// Create the context for network operations with timeout
	timeout := time.Duration(r.MaxTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Set the chain ID
	chainID := big.NewInt(11155111) // Sepolia chain ID

	// Set the contract address
	contractAddress := common.HexToAddress(r.Asset)

	// Set the raw JSON for transferWithAuthorization
	contractJSON := `[{
		"type": "function",
		"name": "transferWithAuthorization",
		"inputs": [
			{"name": "from", "type": "address"},
			{"name": "to", "type": "address"},
			{"name": "value", "type": "uint256"},
			{"name": "validAfter", "type": "uint256"},
			{"name": "validBefore", "type": "uint256"},
			{"name": "nonce", "type": "bytes32"},
			{"name": "v", "type": "uint8"},
			{"name": "r", "type": "bytes32"},
			{"name": "s", "type": "bytes32"}
		],
		"outputs": [],
		"constant": false
	}]`

	// Parse the contract ABI for transferWithAuthorization
	contractABI, err := abi.JSON(strings.NewReader(contractJSON))
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	// Convert the authorization value from string to big.Int
	authValue := new(big.Int)
	_, ok := authValue.SetString(p.Authorization.Value, 10)
	if !ok {
		return SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationValue,
		}, nil
	}

	// Extract the authorization nonce from the payment payload
	authNonceHex := strings.TrimPrefix(p.Authorization.Nonce, "0x")

	// Decode the authorization nonce from hex to bytes
	authNonceBytes, err := hex.DecodeString(authNonceHex)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationNonce,
		}, nil
	}

	// Convert the authorization nonce to a 32 byte slice
	var authNonce [32]byte
	copy(authNonce[:], authNonceBytes)

	// Parse the authorization signature from the payment payload
	authSignature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationSignature,
		}, nil
	}

	// Extract R, S, and V from the authorization signature
	var authSignatureR [32]byte
	var authSignatureS [32]byte
	copy(authSignatureR[:], authSignature[0:32])
	copy(authSignatureS[:], authSignature[32:64])
	authSignatureV := authSignature[64]

	// Convert the V value of the signature if necessary (0/1 → 27/28)
	if authSignatureV == 0 || authSignatureV == 1 {
		authSignatureV += 27
	}

	// Pack the function call data
	txData, err := contractABI.Pack(
		"transferWithAuthorization",
		common.HexToAddress(p.Authorization.From),
		common.HexToAddress(p.Authorization.To),
		authValue,
		big.NewInt(p.Authorization.ValidAfter),
		big.NewInt(p.Authorization.ValidBefore),
		authNonce,
		authSignatureV,
		authSignatureR,
		authSignatureS,
	)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationMessage,
		}, nil
	}

	// Get the RPC URL for the Sepolia test network
	rpcURL := os.Getenv("RPC_URL_SEPOLIA")
	if rpcURL == "" {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("RPC_URL_SEPOLIA environment variable is not set")
	}

	// Dial the Ethereum RPC client
	client, err := clients.NewEthClient(rpcURL)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to dial Ethereum RPC client: %v", err)
	}

	// Get the facilitator private key from the environment
	facilitatorPrivateKeyStr := os.Getenv("PRIVATE_KEY")
	if facilitatorPrivateKeyStr == "" {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("PRIVATE_KEY environment variable is not set")
	}

	// Parse the facilitator private key
	facilitatorPrivateKey, err := crypto.HexToECDSA(strings.TrimPrefix(facilitatorPrivateKeyStr, "0x"))
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to parse facilitator private key: %v", err)
	}

	// Get the facilitator address
	facilitatorAddress := crypto.PubkeyToAddress(facilitatorPrivateKey.PublicKey)

	// Get the pending nonce for the facilitator account
	txNonce, err := client.PendingNonceAt(ctx, facilitatorAddress)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to get pending nonce: %v", err)
	}

	// Get the suggested gas tip cap
	gasTipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to suggest gas tip cap: %v", err)
	}

	// Get the latest block header to get the base fee
	blockHeader, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to get block header: %v", err)
	}

	// Determine the gas fee cap (2x base fee + gas tip cap)
	gasFeeCap := new(big.Int).Add(
		new(big.Int).Mul(blockHeader.BaseFee, big.NewInt(2)),
		gasTipCap,
	)

	// Get the estimated gas limit to set the gas amount
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: facilitatorAddress,
		To:   &contractAddress,
		Data: txData,
	})
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to estimate gas: %v", err)
	}

	// Add 20% buffer to the gas estimate for safety
	gasLimit = gasLimit * 120 / 100

	// Ensure gas limit does not exceed the allowed gas limit
	if r.Extra.GasLimit > 0 && gasLimit > r.Extra.GasLimit {
		return SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInsufficientRequirementsGasLimit,
		}, nil
	}

	// Create the transaction using EIP-1559
	transaction := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     txNonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &contractAddress,
		Value:     big.NewInt(0),
		Data:      txData,
	})

	// Create the signer using EIP-1559
	signer := ethtypes.NewLondonSigner(chainID)

	// Sign the transaction with the facilitator's private key
	signedTx, err := ethtypes.SignTx(transaction, signer, facilitatorPrivateKey)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Send the signed transaction
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return SettleResponse{}, fmt.Errorf("failed to send transaction: %v", err)
	}

	// Return the settle response
	return SettleResponse{
		Success:     true,
		Transaction: signedTx.Hash().Hex(),
	}, nil
}
