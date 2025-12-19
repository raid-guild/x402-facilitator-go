package tests

import (
	"context"
	"database/sql"
	"io"
	"math/big"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	handler "github.com/raid-guild/x402-facilitator-go/api"
	"github.com/raid-guild/x402-facilitator-go/core"
)

var registerMockDriverOnce sync.Once

func setupMockDatabase(t *testing.T, dsnID string) (sqlmock.Sqlmock, string, func()) {
	t.Helper()

	dsn := "sqlmock_db_" + dsnID
	db, mock, err := sqlmock.NewWithDSN(dsn)
	if err != nil {
		t.Fatalf("failed to create mock database: %v", err)
	}

	registerMockDriverOnce.Do(func() {
		driver := db.Driver()
		sql.Register("postgres", driver)
	})

	cleanup := func() {
		db.Close()
	}

	return mock, dsn, cleanup
}

func setupMockEthClient(t *testing.T) {
	t.Helper()

	originalNewEthClient := core.NewEthClient
	t.Cleanup(func() {
		core.NewEthClient = originalNewEthClient
	})

	client := &mockEthClient{
		balanceAt: func(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
			return big.NewInt(1000000), nil
		},
		pendingNonceAt: func(ctx context.Context, account common.Address) (uint64, error) {
			return 1, nil
		},
		suggestGasTipCap: func(ctx context.Context) (*big.Int, error) {
			return big.NewInt(1000), nil
		},
		headerByNumber: func(ctx context.Context, number *big.Int) (*types.Header, error) {
			return &types.Header{
				BaseFee: big.NewInt(1000),
			}, nil
		},
		estimateGas: func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
			return 1000, nil
		},
		sendTransaction: func(ctx context.Context, tx *types.Transaction) error {
			return nil
		},
	}

	core.NewEthClient = func(rpcURL string) (core.EthClientInterface, error) {
		return client, nil
	}
}

func settle(t *testing.T, apiKey string, body string, expectedStatus int, checkResponse func(*testing.T, string)) {
	t.Helper()

	w := httptest.NewRecorder()

	req := httptest.NewRequest("POST", "/settle", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Body = io.NopCloser(strings.NewReader(body))

	handler.Settle(w, req)

	if w.Code != expectedStatus {
		t.Fatalf("expected status %d, got %d. Body: %s", expectedStatus, w.Code, w.Body.String())
	}

	if checkResponse != nil {
		checkResponse(t, w.Body.String())
	}
}

func verify(t *testing.T, apiKey string, body string, expectedStatus int, checkResponse func(*testing.T, string)) {
	t.Helper()

	w := httptest.NewRecorder()

	req := httptest.NewRequest("POST", "/verify", nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Body = io.NopCloser(strings.NewReader(body))

	handler.Verify(w, req)

	if w.Code != expectedStatus {
		t.Fatalf("expected status %d, got %d. Body: %s", expectedStatus, w.Code, w.Body.String())
	}

	if checkResponse != nil {
		checkResponse(t, w.Body.String())
	}
}
