package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestVerify_Authentication(t *testing.T) {

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
		verify(t, "", body, http.StatusOK, nil)
	})

	t.Run("no api key required and irrelevant api key provided", func(t *testing.T) {
		verify(t, "test-api-key", body, http.StatusOK, nil)
	})

	t.Run("static api key required and valid api key provided", func(t *testing.T) {
		t.Setenv("STATIC_API_KEY", "valid-api-key")

		verify(t, "valid-api-key", body, http.StatusOK, nil)
	})

	t.Run("static api key required and invalid api key provided", func(t *testing.T) {
		t.Setenv("STATIC_API_KEY", "valid-api-key")

		verify(t, "invalid-api-key", body, http.StatusUnauthorized, nil)
	})

	t.Run("static api key required and no api key provided", func(t *testing.T) {
		t.Setenv("STATIC_API_KEY", "valid-api-key")

		verify(t, "", body, http.StatusUnauthorized, nil)
	})

	t.Run("database api key required and valid api key provided", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "verify-0")
		defer cleanup()

		t.Setenv("DATABASE_URL", dsn)

		rows := sqlmock.NewRows([]string{"api_key"}).AddRow("valid-api-key")
		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("valid-api-key").
			WillReturnRows(rows)

		verify(t, "valid-api-key", body, http.StatusOK, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("database api key required and invalid api key provided", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "verify-1")
		defer cleanup()

		t.Setenv("DATABASE_URL", dsn)

		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("invalid-api-key").
			WillReturnError(sql.ErrNoRows)

		verify(t, "invalid-api-key", body, http.StatusUnauthorized, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("database api key required and no api key provided", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "test-database-url")

		verify(t, "", body, http.StatusUnauthorized, nil)
	})

}

func TestVerify_VerifyV1ExactSepolia(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	now := time.Now()

	validAfter := now.Add(-2 * time.Minute).Unix()
	validBefore := now.Add(2 * time.Minute).Unix()
	expiredBefore := now.Add(-1 * time.Minute).Unix()
	futureAfter := now.Add(1 * time.Minute).Unix()

	validNonce := "0x" + strings.Repeat("00", 32)
	invalidNonce := "0x" + strings.Repeat("00", 33)
	invalidHexNonce := "0xZZ" + strings.Repeat("00", 30)

	validAddress1 := "0x0000000000000000000000000000000000000001"
	validAddress2 := "0x0000000000000000000000000000000000000002"
	validAddress3 := "0x0000000000000000000000000000000000000003"

	validSignature := "0x" + strings.Repeat("00", 65)
	invalidSignature := "0x" + strings.Repeat("00", 64)
	invalidHexSignature := "0xZZ" + strings.Repeat("00", 63)

	t.Run("invalid body JSON", func(t *testing.T) {
		verify(t, "", `{invalid json}`, http.StatusBadRequest, nil)
	})

	t.Run("missing payment payload", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("invalid payment payload JSON", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentPayload": {invalid json},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusBadRequest, nil)
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			}
		}`
		verify(t, "", body, http.StatusBadRequest, nil)
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {invalid json}
		}`
		verify(t, "", body, http.StatusBadRequest, nil)
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusNotImplemented, nil)
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "other",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusNotImplemented, nil)
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "other",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusNotImplemented, nil)
	})

	t.Run("scheme mismatch", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "other",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("network mismatch", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "other",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusBadRequest, nil)
	})

	t.Run("authorization time window invalid equals", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validAfter, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization time window" {
				t.Errorf("expected invalid reason 'authorization time window', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization time window invalid inverted", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validBefore, 10) + `,
						"validBefore": ` + strconv.FormatInt(validAfter, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization time window" {
				t.Errorf("expected invalid reason 'authorization time window', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization valid before expired", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(expiredBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization valid before" {
				t.Errorf("expected invalid reason 'authorization valid before', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization valid after future", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(futureAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization valid after" {
				t.Errorf("expected invalid reason 'authorization valid after', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization value not a number", func(t *testing.T) {
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
						"value": "not-a-number",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "failed to parse authorization value") {
				t.Errorf("expected invalid reason to contain 'failed to parse authorization value', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization value negative", func(t *testing.T) {
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
						"value": "-1",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization value negative" {
				t.Errorf("expected invalid reason 'authorization value negative', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("max amount required not a number", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "not-a-number",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "failed to parse max amount required") {
				t.Errorf("expected invalid reason to contain 'failed to parse max amount required', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization value exceeds requirements amount", func(t *testing.T) {
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
						"value": "2000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "greater than") {
				t.Errorf("expected invalid reason to contain 'greater than', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("requirements max timeout seconds missing", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "invalid-address",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "requirements max timeout seconds" {
				t.Errorf("expected invalid reason 'requirements max timeout seconds', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("requirements max timeout seconds negative", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "invalid-address",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": -30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "requirements max timeout seconds" {
				t.Errorf("expected invalid reason 'requirements max timeout seconds', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization from invalid", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + validSignature + `",
					"authorization": {
						"from": "invalid-address",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization from" {
				t.Errorf("expected invalid reason 'authorization from', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization from insufficient funds", func(t *testing.T) {
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
						"value": "2000000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "2000000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization from insufficient funds" {
				t.Errorf("expected invalid reason 'authorization from insufficient funds', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization to invalid", func(t *testing.T) {
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
						"to": "invalid-address",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "authorization to" {
				t.Errorf("expected invalid reason 'authorization to', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("requirements pay to invalid", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "invalid-address",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "requirements pay to" {
				t.Errorf("expected invalid reason 'requirements pay to', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization to does not match requirements pay to", func(t *testing.T) {
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
						"to": "` + validAddress1 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "does not match") {
				t.Errorf("expected invalid reason to contain 'does not match', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization nonce hex invalid", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + invalidHexNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "authorization nonce") {
				t.Errorf("expected invalid reason to contain 'authorization nonce', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("authorization nonce length invalid", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + invalidNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "authorization nonce length") {
				t.Errorf("expected invalid reason to contain 'authorization nonce length', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("requirements asset invalid", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "invalid-address",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "requirements asset" {
				t.Errorf("expected invalid reason 'requirements asset', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("requirements extra name empty", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "requirements extra name" {
				t.Errorf("expected invalid reason 'requirements extra name', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("requirements extra version empty", func(t *testing.T) {
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
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": ""
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if response.InvalidReason != "requirements extra version" {
				t.Errorf("expected invalid reason 'requirements extra version', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("signature hex invalid", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + invalidHexSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "signature") {
				t.Errorf("expected invalid reason to contain 'signature', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("signature length invalid", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + invalidSignature + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "signature length") {
				t.Errorf("expected invalid reason to contain 'signature length', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("signature address mismatch", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		sig, _, err := generateEIP712Signature(
			validAddress2,
			validAddress3,
			1000,
			validAfter,
			validBefore,
			validNonce,
			"Coin",
			"1",
			11155111,
		)
		if err != nil {
			t.Fatalf("failed to generate signature: %v", err)
		}
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + sig + `",
					"authorization": {
						"from": "` + validAddress1 + `",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var response struct {
				IsValid       bool   `json:"isValid"`
				InvalidReason string `json:"invalidReason"`
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if response.IsValid {
				t.Errorf("expected valid=false, got valid=true")
			}
			if !strings.Contains(response.InvalidReason, "does not match") {
				t.Errorf("expected invalid reason to contain 'does not match', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("signature address confirmed", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		sig, signerAddress, err := generateEIP712Signature(
			validAddress2,
			validAddress3,
			1000,
			validAfter,
			validBefore,
			validNonce,
			"Coin",
			"1",
			11155111,
		)
		if err != nil {
			t.Fatalf("failed to generate signature: %v", err)
		}
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + sig + `",
					"authorization": {
						"from": "` + signerAddress.Hex() + `",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
			if response.InvalidReason != "" {
				t.Errorf("expected invalid reason to be empty, got '%s'", response.InvalidReason)
			}
			if response.Payer != signerAddress.Hex() {
				t.Errorf("expected payer=%s, got payer=%s", signerAddress.Hex(), response.Payer)
			}
		})
	})

	t.Run("signature V value conversion 27", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		sig, signerAddress, err := generateEIP712SignatureWithLegacyV(
			validAddress2,
			validAddress3,
			1000,
			validAfter,
			validBefore,
			validNonce,
			"Coin",
			"1",
			11155111,
			27,
		)
		if err != nil {
			t.Fatalf("failed to generate signature: %v", err)
		}
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + sig + `",
					"authorization": {
						"from": "` + signerAddress.Hex() + `",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
		})
	})

	t.Run("signature V value conversion 28", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "https://test.node")
		sig, signerAddress, err := generateEIP712SignatureWithLegacyV(
			validAddress2,
			validAddress3,
			1000,
			validAfter,
			validBefore,
			validNonce,
			"Coin",
			"1",
			11155111,
			28,
		)
		if err != nil {
			t.Fatalf("failed to generate signature: %v", err)
		}
		body := `{
			"x402Version": 1,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia",
				"payload": {
					"signature": "` + sig + `",
					"authorization": {
						"from": "` + signerAddress.Hex() + `",
						"to": "` + validAddress2 + `",
						"value": "1000",
						"validAfter": ` + strconv.FormatInt(validAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": "1000",
				"maxTimeoutSeconds": 30,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
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
		})
	})
}
