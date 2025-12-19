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
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/raid-guild/x402-facilitator-go/types"
)

// VerifyExactConfig are the configuration parameters for the verify exact operation.
type VerifyExactConfig struct {
	ChainID int64
	RPCURL  string
}

// VerifyExact verifies the payment on the configured network.
func VerifyExact(c VerifyExactConfig, p types.Payload, r types.PaymentRequirements) (types.VerifyResponse, error) {

	now := time.Now()

	// Verify the authorization time window is valid
	if p.Authorization.ValidAfter >= p.Authorization.ValidBefore {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationTimeWindow,
		}, nil
	}

	// Verify the authorization valid after time is in the past
	validAfter := time.Unix(p.Authorization.ValidAfter, 0)
	if !now.After(validAfter) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValidAfter,
		}, nil
	}

	// Verify the authorization valid before time is in the future
	validBefore := time.Unix(p.Authorization.ValidBefore, 0)
	if !now.Before(validBefore) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValidBefore,
		}, nil
	}

	// Convert the authorization value from string to big.Int
	authValue := new(big.Int)
	_, ok := authValue.SetString(p.Authorization.Value, 10)
	if !ok {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValue,
		}, nil
	}

	// Verify the authorization value is non-negative
	if authValue.Cmp(big.NewInt(0)) < 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValueNegative,
		}, nil
	}

	// Convert the max amount required from string to big.Int
	maxAmount := new(big.Int)
	_, ok = maxAmount.SetString(r.MaxAmountRequired, 10)
	if !ok {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsMaxAmount,
		}, nil
	}

	// Verify the authorization value does not exceed the maximum allowed amount
	if authValue.Cmp(maxAmount) > 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValueExceeded,
		}, nil
	}

	// Verify the requirements max timeout seconds is positive
	if r.MaxTimeoutSeconds <= 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsMaxTimeout,
		}, nil
	}

	// Verify authorization from is a valid address
	if !common.IsHexAddress(p.Authorization.From) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationFromAddress,
		}, nil
	}

	// Convert the authorization from address to common.Address
	fromAddress := common.HexToAddress(p.Authorization.From)

	// Verify requirements asset is a valid address
	if !common.IsHexAddress(r.Asset) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsAsset,
		}, nil
	}

	// Convert the requirements asset address to common.Address
	assetAddress := common.HexToAddress(r.Asset)

	// Set the raw JSON for balanceOf
	balanceOfJSON := `[{
		"type": "function",
		"name": "balanceOf",
		"inputs": [
			{"name": "account", "type": "address"}
		],
		"outputs": [
			{"name": "", "type": "uint256"}
		],
		"constant": true
	}]`

	// Parse the contract ABI for balanceOf
	balanceOfABI, err := abi.JSON(strings.NewReader(balanceOfJSON))
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.VerifyResponse{}, fmt.Errorf("failed to parse balanceOf ABI: %v", err)
	}

	// Pack the balanceOf function call data
	balanceOfData, err := balanceOfABI.Pack("balanceOf", fromAddress)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.VerifyResponse{}, fmt.Errorf("failed to pack balanceOf call data: %v", err)
	}

	// Get the RPC URL for the configured network
	if c.RPCURL == "" {
		// Return an error that will be handled as an internal server error
		return types.VerifyResponse{}, fmt.Errorf("RPC_URL environment variable is not set")
	}

	// Dial the Ethereum RPC client
	client, err := NewEthClient(c.RPCURL)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.VerifyResponse{}, fmt.Errorf("failed to dial RPC client: %v", err)
	}

	// Create the context for network operations with timeout
	timeout := time.Duration(r.MaxTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get the ERC20 token balance of the authorization from account
	balanceResult, err := client.CallContract(ctx, ethereum.CallMsg{
		To:   &assetAddress,
		Data: balanceOfData,
	}, nil)
	if err != nil {
		return types.VerifyResponse{}, fmt.Errorf("failed to get token balance: %v", err)
	}

	// Verify the balance result is not nil
	if balanceResult == nil {
		return types.VerifyResponse{}, fmt.Errorf("failed to get token balance: balance result returned nil")
	}

	// Verify the balance result is 32 bytes
	if len(balanceResult) != 32 {
		return types.VerifyResponse{}, fmt.Errorf("failed to get token balance: balance result is not 32 bytes")
	}

	// Convert the balance result to a big.Int
	balance := new(big.Int).SetBytes(balanceResult)

	// Verify the authorization from account has enough funds
	if balance.Cmp(authValue) < 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInsufficientFunds,
		}, nil
	}

	// Verify authorization to is a valid address
	if !common.IsHexAddress(p.Authorization.To) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationToAddress,
		}, nil
	}

	// Verify requirements pay to is a valid address
	if !common.IsHexAddress(r.PayTo) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsPayToAddress,
		}, nil
	}

	// Verify the authorization to address matches the required pay to address
	if common.HexToAddress(p.Authorization.To) != common.HexToAddress(r.PayTo) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationToAddressMismatch,
		}, nil
	}

	// Decode the nonce from hex to bytes
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(p.Authorization.Nonce, "0x"))
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationNonce,
		}, nil
	}

	// Validate the nonce is exactly 32 bytes
	if len(nonceBytes) != 32 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationNonceLength,
		}, nil
	}

	// Verify requirements extra name is not empty
	if r.Extra.Name == "" {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsExtraName,
		}, nil
	}

	// Verify requirements extra version is not empty
	if r.Extra.Version == "" {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsExtraVersion,
		}, nil
	}

	// Convert the chain ID to hex or decimal
	bigChainID := big.NewInt(c.ChainID)
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
			"value":       authValue,
			"validAfter":  big.NewInt(p.Authorization.ValidAfter),
			"validBefore": big.NewInt(p.Authorization.ValidBefore),
			"nonce":       nonce,
		},
	}

	// Compute the domain hash
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidTypedDataDomain,
		}, nil
	}

	// Compute the message hash
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidTypedDataMessage,
		}, nil
	}

	// Construct the signature hash
	rawData := append(append([]byte("\x19\x01"), domainSeparator...), typedDataHash...)
	sighash := crypto.Keccak256(rawData)

	// Parse the payload signature
	signature, err := common.ParseHexOrString(p.Signature)
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationSignature,
		}, nil
	}

	// Verify the signature is exactly 65 bytes (32 bytes r + 32 bytes s + 1 byte v)
	if len(signature) != 65 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationSignatureLength,
		}, nil
	}

	// Convert the V value of the signature if necessary (27/28 → 0/1)
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27
	}

	// Recover the public key
	pubkey, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationSignatureHash,
		}, nil
	}

	// Verify public key length
	if len(pubkey) != 65 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationPubkeyLength,
		}, nil
	}

	// Unmarshal the public key
	recoveredPubkey, err := crypto.UnmarshalPubkey(pubkey)
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationPubkey,
		}, nil
	}

	// Convert the public key to an address
	sender := crypto.PubkeyToAddress(*recoveredPubkey)

	// Verify the sender matches the authorization from
	if sender != fromAddress {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationSenderMismatch,
		}, nil
	}

	// Return verify response valid with the payer address
	return types.VerifyResponse{
		IsValid: true,
		Payer:   sender.Hex(),
	}, nil
}
