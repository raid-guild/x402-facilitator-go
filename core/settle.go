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
	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/raid-guild/x402-facilitator-go/types"
)

// SettleExactConfig is the SettleExact configuration.
type SettleExactConfig struct {
	ChainID    int64
	RPCURL     string
	PrivateKey string
}

// SettleExactParams is the SettleExact parameters.
type SettleExactParams struct {
	Signature                string
	AuthorizationFrom        string
	AuthorizationTo          string
	AuthorizationValue       string
	AuthorizationValidAfter  string
	AuthorizationValidBefore string
	AuthorizationNonce       string
	Asset                    string
	MaxTimeoutSeconds        int64
	ExtraGasLimit            uint64
}

// SettleExact settles the payment on the configured network.
func SettleExact(c SettleExactConfig, p SettleExactParams) (types.SettleResponse, error) {

	// Verify the RPC URL is set
	if c.RPCURL == "" {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("RPC URL is not set")
	}

	// Verify the private key is set
	if c.PrivateKey == "" {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("private key is not set")
	}

	// Convert the authorization value from string to big.Int
	authValue, ok := new(big.Int).SetString(p.AuthorizationValue, 10)
	if !ok {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationValue,
		}, nil
	}

	// Convert the authorization valid after from string to big.Int
	authValidAfter, ok := new(big.Int).SetString(p.AuthorizationValidAfter, 10)
	if !ok {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationValidAfter,
		}, nil
	}

	// Convert the authorization valid before from string to big.Int
	authValidBefore, ok := new(big.Int).SetString(p.AuthorizationValidBefore, 10)
	if !ok {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationValidBefore,
		}, nil
	}

	// Extract the authorization nonce from the payment payload
	authNonceHex := strings.TrimPrefix(p.AuthorizationNonce, "0x")

	// Decode the authorization nonce from hex to bytes
	authNonceBytes, err := hex.DecodeString(authNonceHex)
	if err != nil {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationNonce,
		}, nil
	}

	// Parse the authorization signature from the payment payload
	authSignature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInvalidAuthorizationSignature,
		}, nil
	}

	// Parse the facilitator private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(c.PrivateKey, "0x"))
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to parse private key: %v", err)
	}

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

	// Convert the authorization nonce to a 32 byte slice
	var authNonce [32]byte
	copy(authNonce[:], authNonceBytes)

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
		common.HexToAddress(p.AuthorizationFrom),
		common.HexToAddress(p.AuthorizationTo),
		authValue,
		authValidAfter,
		authValidBefore,
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

	// Set the chain ID
	chainID := big.NewInt(c.ChainID)

	// Set the contract address
	contractAddress := common.HexToAddress(p.Asset)

	// Get the facilitator address from the private key
	facilitatorAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Set the timeout duration for network operations
	timeout := time.Duration(p.MaxTimeoutSeconds) * time.Second

	// Create the context for network operations with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Dial the Ethereum RPC client
	client, err := NewEthClient(c.RPCURL)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to dial RPC client: %v", err)
	}

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
	if p.ExtraGasLimit > 0 && gasLimit > p.ExtraGasLimit {
		return types.SettleResponse{
			Success:     false,
			ErrorReason: types.ErrorReasonInsufficientGasLimit,
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
	signedTx, err := ethtypes.SignTx(transaction, signer, privateKey)
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

	// Wait for the transaction to be settled
	receipt, err := bind.WaitMined(ctx, client, signedTx.Hash())
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("failed to wait for transaction: %v", err)
	}

	// Verify the transaction receipt status
	if receipt.Status != ethtypes.ReceiptStatusSuccessful {
		// Return an error that will be handled as an internal server error
		return types.SettleResponse{}, fmt.Errorf("transaction failed with status %d", receipt.Status)
	}

	// Return a successful settle response with the transaction hash
	return types.SettleResponse{
		Success:     true,
		Transaction: signedTx.Hash().Hex(),
	}, nil
}
