package tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func generateEIP712Signature(
	to string,
	asset string,
	value int64,
	validAfter int64,
	validBefore int64,
	nonce string,
	assetName string,
	assetVersion string,
	chainID int64,
) (string, common.Address, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return "", common.Address{}, err
	}

	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	signerAddressHex := signerAddress.Hex()

	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(nonce, "0x"))
	if err != nil {
		return "", common.Address{}, err
	}
	var nonceArray [32]byte
	copy(nonceArray[:], nonceBytes)

	bigChainID := big.NewInt(chainID)
	hexChainID := math.HexOrDecimal256(*bigChainID)

	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": []apitypes.Type{
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              assetName,
			Version:           assetVersion,
			ChainId:           &hexChainID,
			VerifyingContract: asset,
		},
		Message: apitypes.TypedDataMessage{
			"from":        signerAddressHex,
			"to":          to,
			"value":       big.NewInt(value),
			"validAfter":  big.NewInt(validAfter),
			"validBefore": big.NewInt(validBefore),
			"nonce":       nonceArray,
		},
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "", common.Address{}, err
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return "", common.Address{}, err
	}

	rawData := append(append([]byte("\x19\x01"), domainSeparator...), typedDataHash...)
	sighash := crypto.Keccak256(rawData)

	signature, err := crypto.Sign(sighash, privateKey)
	if err != nil {
		return "", common.Address{}, err
	}

	return "0x" + hex.EncodeToString(signature), signerAddress, nil
}

func generateEIP712SignatureWithLegacyV(
	to string,
	asset string,
	value int64,
	validAfter int64,
	validBefore int64,
	nonce string,
	assetName string,
	assetVersion string,
	chainID int64,
	targetV byte,
) (string, common.Address, error) {
	if targetV != 27 && targetV != 28 {
		return "", common.Address{}, fmt.Errorf("targetV must be 27 or 28, got %d", targetV)
	}

	desiredRecoveryID := targetV - 27

	maxAttempts := 100
	for range maxAttempts {
		sig, signerAddress, err := generateEIP712Signature(
			to,
			asset,
			value,
			validAfter,
			validBefore,
			nonce,
			assetName,
			assetVersion,
			chainID,
		)
		if err != nil {
			return "", common.Address{}, err
		}

		sigBytes, err := hex.DecodeString(strings.TrimPrefix(sig, "0x"))
		if err != nil {
			return "", common.Address{}, err
		}

		recoveryID := sigBytes[64]
		if recoveryID == desiredRecoveryID {
			sigBytes[64] += 27
			return "0x" + hex.EncodeToString(sigBytes), signerAddress, nil
		}
	}

	return "", common.Address{}, fmt.Errorf(
		"failed to generate signature with recovery ID %d after %d attempts",
		desiredRecoveryID,
		maxAttempts,
	)
}

type mockEthClient struct {
	pendingNonceAt   func(ctx context.Context, account common.Address) (uint64, error)
	suggestGasTipCap func(ctx context.Context) (*big.Int, error)
	headerByNumber   func(ctx context.Context, number *big.Int) (*types.Header, error)
	estimateGas      func(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	sendTransaction  func(ctx context.Context, tx *types.Transaction) error
}

func (m *mockEthClient) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	if m.pendingNonceAt != nil {
		return m.pendingNonceAt(ctx, account)
	}
	return 0, nil
}

func (m *mockEthClient) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if m.suggestGasTipCap != nil {
		return m.suggestGasTipCap(ctx)
	}
	return big.NewInt(1000000000), nil
}

func (m *mockEthClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if m.headerByNumber != nil {
		return m.headerByNumber(ctx, number)
	}
	return &types.Header{
		BaseFee: big.NewInt(20000000000),
	}, nil
}

func (m *mockEthClient) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	if m.estimateGas != nil {
		return m.estimateGas(ctx, msg)
	}
	return 21000, nil
}

func (m *mockEthClient) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	if m.sendTransaction != nil {
		return m.sendTransaction(ctx, tx)
	}
	return nil
}
