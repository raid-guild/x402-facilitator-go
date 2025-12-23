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

// VerifyExactConfig is the VerifyExact configuration.
type VerifyExactConfig struct {
	ChainID int64
	RPCURL  string
}

// VerifyExactParams is the VerifyExact parameters.
type VerifyExactParams struct {
	Signature                string
	AuthorizationFrom        string
	AuthorizationTo          string
	AuthorizationValue       string
	AuthorizationValidAfter  string
	AuthorizationValidBefore string
	AuthorizationNonce       string
	Asset                    string
	PayTo                    string
	Amount                   string
	MaxTimeoutSeconds        int64
	ExtraName                string
	ExtraVersion             string
}

// VerifyExact verifies the payment on the configured network.
func VerifyExact(c VerifyExactConfig, p VerifyExactParams) (types.VerifyResponse, error) {

	// Verify the RPC URL is set
	if c.RPCURL == "" {
		// Return an error that will be handled as an internal server error
		return types.VerifyResponse{}, fmt.Errorf("RPC URL is not set")
	}

	// Verify authorization from is a valid address
	if !common.IsHexAddress(p.AuthorizationFrom) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationFrom,
		}, nil
	}

	// Verify authorization to is a valid address
	if !common.IsHexAddress(p.AuthorizationTo) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationTo,
		}, nil
	}

	// Verify requirements asset is a valid address
	if !common.IsHexAddress(p.Asset) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsAsset,
		}, nil
	}

	// Verify requirements pay to is a valid address
	if !common.IsHexAddress(p.PayTo) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsPayTo,
		}, nil
	}

	// Verify the authorization to address matches the requirements pay to address
	if common.HexToAddress(p.AuthorizationTo) != common.HexToAddress(p.PayTo) {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationToMismatch,
		}, nil
	}

	// Convert the authorization value from string to big.Int
	authValue, ok := new(big.Int).SetString(p.AuthorizationValue, 10)
	if !ok {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValue,
		}, nil
	}

	// Convert requirements amount from string to big.Int
	amount, ok := new(big.Int).SetString(p.Amount, 10)
	if !ok {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsAmount,
		}, nil
	}

	// Set big.Int zero
	zero := big.NewInt(0)

	// Verify the authorization value is positive
	if authValue.Cmp(zero) <= 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValueNegative,
		}, nil
	}

	// Verify the authorization value matches the required amount
	if authValue.Cmp(amount) != 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValueMismatch,
		}, nil
	}

	// Convert the authorization valid after from string to big.Int
	authValidAfter, ok := new(big.Int).SetString(p.AuthorizationValidAfter, 10)
	if !ok {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValidAfter,
		}, nil
	}

	// Convert the authorization valid before from string to big.Int
	authValidBefore, ok := new(big.Int).SetString(p.AuthorizationValidBefore, 10)
	if !ok {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValidBefore,
		}, nil
	}

	// Verify the authorization time window is valid
	if authValidAfter.Cmp(authValidBefore) >= 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationTimeWindow,
		}, nil
	}

	// Set big.Int now
	now := big.NewInt(time.Now().Unix())

	// Verify the authorization valid after time is in the past
	if authValidAfter.Cmp(now) >= 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValidAfter,
		}, nil
	}

	// Verify the authorization valid before time is in the future
	if authValidBefore.Cmp(now) <= 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationValidBefore,
		}, nil
	}

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

	// Decode the nonce from hex to bytes
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(p.AuthorizationNonce, "0x"))
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

	// Verify the requirements max timeout seconds is positive
	if p.MaxTimeoutSeconds <= 0 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsMaxTimeout,
		}, nil
	}

	// Verify requirements extra name is not empty
	if p.ExtraName == "" {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsExtraName,
		}, nil
	}

	// Verify requirements extra version is not empty
	if p.ExtraVersion == "" {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidRequirementsExtraVersion,
		}, nil
	}

	// Set the timeout duration for network operations
	timeout := time.Duration(p.MaxTimeoutSeconds) * time.Second

	// Create the context for network operations with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Dial the Ethereum RPC client
	client, err := NewEthClient(c.RPCURL)
	if err != nil {
		// Return an error that will be handled as an internal server error
		return types.VerifyResponse{}, fmt.Errorf("failed to dial RPC client: %v", err)
	}

	// Convert the authorization from address to common.Address
	fromAddress := common.HexToAddress(p.AuthorizationFrom)

	// Convert the requirements asset address to common.Address
	assetAddress := common.HexToAddress(p.Asset)

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
		return types.VerifyResponse{}, fmt.Errorf("failed to get token balance: balance result is nil")
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
			Name:              p.ExtraName,
			Version:           p.ExtraVersion,
			ChainId:           &hexChainID,
			VerifyingContract: p.Asset,
		},
		Message: apitypes.TypedDataMessage{
			"from":        p.AuthorizationFrom,
			"to":          p.AuthorizationTo,
			"value":       authValue,
			"validAfter":  authValidAfter,
			"validBefore": authValidBefore,
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

	// Convert the V value of the signature if necessary (27/28 → 0/1)
	if signature[64] == 27 || signature[64] == 28 {
		signature[64] -= 27
	}

	// Recover the public key
	pubkeyBytes, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationPubkey,
		}, nil
	}

	// Verify the public key length is exactly 65 bytes
	if len(pubkeyBytes) != 65 {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationPubkeyLength,
		}, nil
	}

	// Unmarshal the public key
	pubkey, err := crypto.UnmarshalPubkey(pubkeyBytes)
	if err != nil {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationPubkey,
		}, nil
	}

	// Convert the public key to an address
	pubkeyAddress := crypto.PubkeyToAddress(*pubkey)

	// Verify the public key address matches the authorization from address
	if pubkeyAddress != fromAddress {
		return types.VerifyResponse{
			IsValid:       false,
			InvalidReason: types.InvalidReasonInvalidAuthorizationPubkeyMismatch,
		}, nil
	}

	// Return a valid verify response with the payer address
	return types.VerifyResponse{
		IsValid: true,
		Payer:   p.AuthorizationFrom,
	}, nil
}
