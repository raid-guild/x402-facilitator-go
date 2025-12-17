package tests

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSettle_Authentication(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	body := `{
		"x402Version": 1,
		"paymentPayload": {
			"scheme": "exact",
			"network": "sepolia"
		},
		"paymentRequirements": {
			"scheme": "exact",
			"network": "sepolia"
		}
	}`

	t.Run("no api key required and no api key provided", func(t *testing.T) {
		settle(t, "", body, http.StatusOK, nil)
	})

	t.Run("no api key required and irrelevant api key provided", func(t *testing.T) {
		settle(t, "test-api-key", body, http.StatusOK, nil)
	})

	t.Run("static api key required and valid api key provided", func(t *testing.T) {
		t.Setenv("STATIC_API_KEY", "valid-api-key")

		settle(t, "valid-api-key", body, http.StatusOK, nil)
	})

	t.Run("static api key required and invalid api key provided", func(t *testing.T) {
		t.Setenv("STATIC_API_KEY", "valid-api-key")

		settle(t, "invalid-api-key", body, http.StatusUnauthorized, nil)
	})

	t.Run("static api key required and no api key provided", func(t *testing.T) {
		t.Setenv("STATIC_API_KEY", "valid-api-key")

		settle(t, "", body, http.StatusUnauthorized, nil)
	})

	t.Run("database api key required and valid api key provided", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "settle-0")
		defer cleanup()

		t.Setenv("DATABASE_URL", dsn)

		rows := sqlmock.NewRows([]string{"api_key"}).AddRow("valid-api-key")
		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("valid-api-key").
			WillReturnRows(rows)

		settle(t, "valid-api-key", body, http.StatusOK, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("database api key required and invalid api key provided", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "settle-1")
		defer cleanup()

		t.Setenv("DATABASE_URL", dsn)

		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("invalid-api-key").
			WillReturnError(sql.ErrNoRows)

		settle(t, "invalid-api-key", body, http.StatusUnauthorized, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("database api key required and no api key provided", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "test-database-url")

		settle(t, "", body, http.StatusUnauthorized, nil)
	})

}

func TestSettle_SettleV1ExactSepolia(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	now := time.Now()

	validAfter := now.Add(-2 * time.Minute).Unix()
	validBefore := now.Add(2 * time.Minute).Unix()

	validNonce := "0x" + strings.Repeat("00", 32)

	validAddress1 := "0x0000000000000000000000000000000000000001"
	validAddress2 := "0x0000000000000000000000000000000000000002"
	validAddress3 := "0x0000000000000000000000000000000000000003"

	validSignature := "0x" + strings.Repeat("00", 65)

	privateKey, _ := crypto.GenerateKey()
	privateKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privateKey))

	t.Run("invalid body JSON", func(t *testing.T) {
		settle(t, "", `{invalid json}`, http.StatusBadRequest, nil)
	})

	t.Run("missing payment payload", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("invalid payment payload JSON", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {invalid json},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("missing payment requirements", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			}
		}`
		settle(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("invalid payment requirements JSON", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {invalid json}
		}`
		settle(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("unsupported x402 version", func(t *testing.T) {
		body := `{
			"x402Version": 0,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusNotImplemented, nil)
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "other",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "other",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusNotImplemented, nil)
	})

	t.Run("unsupported network", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "other",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "other",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusNotImplemented, nil)
	})

	t.Run("RPC_URL_SEPOLIA not set", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
			if response.ErrorReason != "RPC_URL_SEPOLIA environment variable is not set" {
				t.Errorf("expected error reason 'RPC_URL_SEPOLIA environment variable is not set', got '%s'", response.ErrorReason)
			}
		})
	})

	t.Run("PRIVATE_KEY not set", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
			if response.ErrorReason != "PRIVATE_KEY environment variable is not set" {
				t.Errorf("expected error reason 'PRIVATE_KEY environment variable is not set', got '%s'", response.ErrorReason)
			}
		})
	})

	t.Run("PRIVATE_KEY invalid", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		t.Setenv("PRIVATE_KEY", "invalid-hex-key")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
			if !strings.Contains(response.ErrorReason, "failed to parse facilitator private key") {
				t.Errorf("expected error reason to contain 'failed to parse facilitator private key', got '%s'", response.ErrorReason)
			}
		})
	})

	t.Run("success", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		t.Setenv("PRIVATE_KEY", privateKeyHex)
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": 1000,
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		settle(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
		})
	})
}
