package tests

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type mockEthClient struct {
	codeAt             func(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	callContract       func(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	pendingNonceAt     func(ctx context.Context, account common.Address) (uint64, error)
	suggestGasTipCap   func(ctx context.Context) (*big.Int, error)
	headerByNumber     func(ctx context.Context, number *big.Int) (*types.Header, error)
	estimateGas        func(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	sendTransaction    func(ctx context.Context, tx *types.Transaction) error
	transactionReceipt func(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

func (m *mockEthClient) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	if m.codeAt != nil {
		return m.codeAt(ctx, account, blockNumber)
	}
	return []byte{}, nil
}

func (m *mockEthClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if m.callContract != nil {
		return m.callContract(ctx, msg, blockNumber)
	}
	balance := big.NewInt(1000)
	balanceBytes := make([]byte, 32)
	balance.FillBytes(balanceBytes)
	return balanceBytes, nil
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
	return big.NewInt(1000), nil
}

func (m *mockEthClient) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if m.headerByNumber != nil {
		return m.headerByNumber(ctx, number)
	}
	return &types.Header{
		BaseFee: big.NewInt(1000),
	}, nil
}

func (m *mockEthClient) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	if m.estimateGas != nil {
		return m.estimateGas(ctx, msg)
	}
	return 1000, nil
}

func (m *mockEthClient) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	if m.sendTransaction != nil {
		return m.sendTransaction(ctx, tx)
	}
	return nil
}

func (m *mockEthClient) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	if m.transactionReceipt != nil {
		return m.transactionReceipt(ctx, txHash)
	}
	return &types.Receipt{
		Status: types.ReceiptStatusSuccessful,
	}, nil
}
