package core

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/raid-guild/x402-facilitator-go/types"
)

// SettleExactConfig are the configuration parameters for the settle exact operation.
type SettleExactConfig struct {
	ChainID    int64
	RPCURL     string
	PrivateKey string
}

// SettleExact settles the payment on the configured network.
func SettleExact(c SettleExactConfig, p types.Payload, r types.PaymentRequirements) (types.SettleResponse, error) {

	// Verify the requirements max timeout seconds is positive
	if r.MaxTimeoutSeconds <= 0 {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidRequirementsMaxTimeout,
		}, nil
	}

	// Create the context for network operations with timeout
	timeout := time.Duration(r.MaxTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Set the chain ID
	chainID := big.NewInt(c.ChainID)

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
		return types.SettleResponse{}, fmt.Errorf("failed to parse contract ABI: %v", err)
	}

	// Convert the authorization value from string to big.Int
	authValue := new(big.Int)
	_, ok := authValue.SetString(p.Authorization.Value, 10)
	if !ok {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationValue,
		}, nil
	}

	// Extract the authorization nonce from the payment payload
	authNonceHex := strings.TrimPrefix(p.Authorization.Nonce, "0x")

	// Decode the authorization nonce from hex to bytes
	authNonceBytes, err := hex.DecodeString(authNonceHex)
	if err != nil {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationNonce,
		}, nil
	}

	// Validate the nonce is exactly 32 bytes
	if len(authNonceBytes) != 32 {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationNonceLength,
		}, nil
	}

	// Convert the authorization nonce to a 32 byte slice
	var authNonce [32]byte
	copy(authNonce[:], authNonceBytes)

	// Parse the authorization signature from the payment payload
	authSignature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationSignature,
		}, nil
	}

	// Verify the signature is exactly 65 bytes (32 bytes r + 32 bytes s + 1 byte v)
	if len(authSignature) != 65 {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationSignatureLength,
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
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationMessage,
		}, nil
	}

	// Get the RPC URL for the configured network
	if c.RPCURL == "" {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("RPC_URL environment variable is not set")
	}

	// Dial the Ethereum RPC client
	client, err := NewEthClient(c.RPCURL)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to dial Ethereum RPC client: %v", err)
	}

	// Get the facilitator private key from the environment
	if c.PrivateKey == "" {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("PRIVATE_KEY environment variable is not set")
	}

	// Parse the facilitator private key
	facilitatorPrivateKey, err := crypto.HexToECDSA(strings.TrimPrefix(c.PrivateKey, "0x"))
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to parse facilitator private key: %v", err)
	}

	// Get the facilitator address
	facilitatorAddress := crypto.PubkeyToAddress(facilitatorPrivateKey.PublicKey)

	// Get the pending nonce for the facilitator account
	txNonce, err := client.PendingNonceAt(ctx, facilitatorAddress)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to get pending nonce: %v", err)
	}

	// Get the suggested gas tip cap
	gasTipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to suggest gas tip cap: %v", err)
	}

	// Get the latest block header to get the base fee
	blockHeader, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to get block header: %v", err)
	}

	// Verify the block header base fee is not nil
	if blockHeader.BaseFee == nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("block header missing base fee: network may not support EIP-1559")
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
		return types.SettleResponse{}, fmt.Errorf("failed to estimate gas: %v", err)
	}

	// Add 20% buffer to the gas estimate for safety
	gasLimit = gasLimit * 120 / 100

	// Ensure gas limit does not exceed the allowed gas limit
	if r.Extra.GasLimit > 0 && gasLimit > r.Extra.GasLimit {
		return types.SettleResponse{
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
		return types.SettleResponse{}, fmt.Errorf("failed to sign transaction: %v", err)
	}

	// Send the signed transaction
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to send transaction: %v", err)
	}

	// Return the settle response
	return types.SettleResponse{
		Success:     true,
		Transaction: signedTx.Hash().Hex(),
	}, nil
}
