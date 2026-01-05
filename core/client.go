package core

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/raid-guild/x402-facilitator-go/utils"
)

// EthClientInterface defines the interface for Ethereum client.
type EthClientInterface interface {
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

var (
	// ethClientCache stores cached Ethereum clients by RPC URL (reused with warm instances)
	ethClientCache = utils.NewKeyedCache[EthClientInterface]()
)

// NewEthClient creates a new Ethereum client, reusing cached clients with warm instances.
// This function is declared as a variable so that it can be overridden in tests.
var NewEthClient = func(rpcURL string) (EthClientInterface, error) {

	// Get the cached Ethereum client (reused with warm instances)
	return ethClientCache.Get(rpcURL, func() (EthClientInterface, error) {

		// Dial the Ethereum client
		client, err := ethclient.Dial(rpcURL)
		if err != nil {
			return nil, err
		}

		// Return the Ethereum client
		return client, nil
	})
}
