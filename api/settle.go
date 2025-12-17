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
	Success     bool   `json:"success"`
	Transaction string `json:"transaction"`
	ErrorReason string `json:"errorReason"`
}

// Settle is the handler function called by Vercel.
func Settle(w http.ResponseWriter, r *http.Request) {

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

		// Check the payment scheme
		if paymentPayload.Scheme == types.SchemeExact {

			// Check the payment network
			if paymentPayload.Network == types.NetworkSepolia {

				// Settle the payment by sending a transaction on the Sepolia test network
				response := settleV1ExactSepolia(paymentPayload, paymentRequirements)

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

func settleV1ExactSepolia(p types.PaymentPayload, r types.PaymentRequirements) SettleResponse {

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
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to parse ABI: %v", err),
		}
	}

	// Extract the authorization nonce from the payment payload
	authNonceHex := strings.TrimPrefix(p.Payload.Authorization.Nonce, "0x")

	// Decode the authorization nonce from hex to bytes
	authNonceBytes, err := hex.DecodeString(authNonceHex)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to decode nonce: %v", err),
		}
	}

	// Convert the authorization nonce to a 32 byte slice
	var authNonce [32]byte
	copy(authNonce[:], authNonceBytes)

	// Parse the authorization signature from the payment payload
	authSignature, err := common.ParseHexOrString(p.Payload.Signature)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to parse signature: %v", err),
		}
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
		common.HexToAddress(p.Payload.Authorization.From),
		common.HexToAddress(p.Payload.Authorization.To),
		big.NewInt(p.Payload.Authorization.Value),
		big.NewInt(p.Payload.Authorization.ValidAfter),
		big.NewInt(p.Payload.Authorization.ValidBefore),
		authNonce,
		authSignatureV,
		authSignatureR,
		authSignatureS,
	)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to pack function call: %v", err),
		}
	}

	// Get the RPC URL for the Sepolia test network
	rpcURL := os.Getenv("RPC_URL_SEPOLIA")
	if rpcURL == "" {
		return SettleResponse{
			Success:     false,
			ErrorReason: "RPC_URL_SEPOLIA environment variable is not set",
		}
	}

	// Dial the Ethereum RPC client
	client, err := clients.NewEthClient(rpcURL)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to dial RPC client: %v", err),
		}
	}

	// Get the facilitator private key from the environment
	facilitatorPrivateKeyStr := os.Getenv("PRIVATE_KEY")
	if facilitatorPrivateKeyStr == "" {
		return SettleResponse{
			Success:     false,
			ErrorReason: "PRIVATE_KEY environment variable is not set",
		}
	}

	// Parse the facilitator private key
	facilitatorPrivateKey, err := crypto.HexToECDSA(strings.TrimPrefix(facilitatorPrivateKeyStr, "0x"))
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to parse facilitator private key: %v", err),
		}
	}

	// Get the facilitator address
	facilitatorAddress := crypto.PubkeyToAddress(facilitatorPrivateKey.PublicKey)

	// Get the pending nonce for the facilitator account
	txNonce, err := client.PendingNonceAt(ctx, facilitatorAddress)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to get pending nonce: %v", err),
		}
	}

	// Get the suggested gas tip cap
	gasTipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to suggest gas tip cap: %v", err),
		}
	}

	// Get the latest block header to get the base fee
	blockHeader, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to get block header: %v", err),
		}
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
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to estimate gas: %v", err),
		}
	}

	// Add 20% buffer to the gas estimate for safety
	gasLimit = gasLimit * 120 / 100

	// Ensure gas limit does not exceed the allowed gas limit
	if r.Extra.GasLimit > 0 && gasLimit > r.Extra.GasLimit {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("estimated gas (%d) exceeds maximum allowed (%d)", gasLimit, r.Extra.GasLimit),
		}
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
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to sign transaction: %v", err),
		}
	}

	// Send the signed transaction
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return SettleResponse{
			Success:     false,
			ErrorReason: fmt.Sprintf("failed to send transaction: %v", err),
		}
	}

	// Return the settle response
	return SettleResponse{
		Success:     true,
		Transaction: signedTx.Hash().Hex(),
	}
}
