package tests

import (
	"context"
	"database/sql"
	"encoding/json"
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
		codeAt: func(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
			return []byte{}, nil
		},
		callContract: func(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
			balance := big.NewInt(1000)
			balanceBytes := make([]byte, 32)
			balance.FillBytes(balanceBytes)
			return balanceBytes, nil
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
		transactionReceipt: func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			return &types.Receipt{
				Status: types.ReceiptStatusSuccessful,
			}, nil
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
func expectErrorReason(expectedReason string) func(*testing.T, string) {
	return func(t *testing.T, body string) {
		t.Helper()
		var response struct {
			Success     bool   `json:"success"`
			ErrorReason string `json:"errorReason"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("failed to decode response: %v. Body: %s", err, body)
		}
		if response.Success {
			t.Errorf("expected success=false, got success=true")
		}
		if response.ErrorReason != expectedReason {
			t.Errorf("expected error reason '%s', got '%s'", expectedReason, response.ErrorReason)
		}
	}
}

func expectSuccess() func(*testing.T, string) {
	return func(t *testing.T, body string) {
		t.Helper()
		var response struct {
			Success     bool   `json:"success"`
			Transaction string `json:"transaction"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("failed to decode response: %v. Body: %s", err, body)
		}
		if !response.Success {
			t.Errorf("expected success=true, got success=false")
		}
		if response.Transaction == "" {
			t.Errorf("expected tx hash to be set, got '%s'", response.Transaction)
		}
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

func expectInvalidReason(expectedReason string) func(*testing.T, string) {
	return func(t *testing.T, body string) {
		t.Helper()
		var response struct {
			IsValid       bool   `json:"isValid"`
			InvalidReason string `json:"invalidReason"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("failed to decode response: %v. Body: %s", err, body)
		}
		if response.IsValid {
			t.Errorf("expected isValid=false, got isValid=true")
		}
		if response.InvalidReason != expectedReason {
			t.Errorf("expected invalid reason '%s', got '%s'", expectedReason, response.InvalidReason)
		}
	}
}

func expectValid(signerAddress common.Address) func(*testing.T, string) {
	return func(t *testing.T, body string) {
		t.Helper()
		var response struct {
			IsValid       bool   `json:"isValid"`
			Payer         string `json:"payer"`
			InvalidReason string `json:"invalidReason"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil {
			t.Fatalf("failed to decode response: %v. Body: %s", err, body)
		}
		if !response.IsValid {
			t.Errorf("expected valid=true, got valid=false. InvalidReason: %s", response.InvalidReason)
		}
		if response.Payer != signerAddress.Hex() {
			t.Errorf("expected payer=%s, got payer=%s", signerAddress.Hex(), response.Payer)
		}
	}
}
