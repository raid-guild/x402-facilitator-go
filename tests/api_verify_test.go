package tests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

var authenticationBody = `{
	"x402Version": 1,
	"paymentPayload": {
		"scheme": "exact",
		"network": "sepolia",
		"payload": {
			"signature": "0x...",
			"authorization": {
				"from": "0x...",
				"to": "0x...",
				"value": 1000,
				"validAfter": 1718201600,
				"validBefore": 1718201600,
				"nonce": "0x..."
			}
		}
	},
	"paymentRequirements": {
		"scheme": "exact",
		"network": "sepolia",
		"maxAmountRequired": 1000,
		"asset": "0x...",
		"payTo": "0x...",
		"extra": {
			"assetName": "Coin",
			"assetVersion": "1"
		}
	}
}`

func TestVerify_Authentication(t *testing.T) {

	t.Run("with no api key set and no api key in the request header", func(t *testing.T) {
		verify(t, "", authenticationBody, http.StatusOK, nil)
	})

	t.Run("with no api key set and irrelevant api key in the request header", func(t *testing.T) {
		verify(t, "test-api-key", authenticationBody, http.StatusOK, nil)
	})

	t.Run("with static api key set and valid api key in the request header", func(t *testing.T) {
		os.Setenv("STATIC_API_KEY", "valid-api-key")
		defer os.Unsetenv("STATIC_API_KEY")

		verify(t, "valid-api-key", authenticationBody, http.StatusOK, nil)
	})

	t.Run("with static api key set and invalid api key in the request header", func(t *testing.T) {
		os.Setenv("STATIC_API_KEY", "valid-api-key")
		defer os.Unsetenv("STATIC_API_KEY")

		verify(t, "invalid-api-key", authenticationBody, http.StatusUnauthorized, nil)
	})

	t.Run("with static api key set and no api key in the request header", func(t *testing.T) {
		os.Setenv("STATIC_API_KEY", "valid-api-key")
		defer os.Unsetenv("STATIC_API_KEY")

		verify(t, "", authenticationBody, http.StatusUnauthorized, nil)
	})

	t.Run("with database url set and valid api key in the request header", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "verify-0")
		defer cleanup()

		os.Setenv("DATABASE_URL", dsn)
		defer os.Unsetenv("DATABASE_URL")

		rows := sqlmock.NewRows([]string{"api_key"}).AddRow("valid-api-key")
		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("valid-api-key").
			WillReturnRows(rows)

		verify(t, "valid-api-key", authenticationBody, http.StatusOK, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("with database url set and invalid api key in the request header", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "verify-1")
		defer cleanup()

		os.Setenv("DATABASE_URL", dsn)
		defer os.Unsetenv("DATABASE_URL")

		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("invalid-api-key").
			WillReturnError(sql.ErrNoRows)

		verify(t, "invalid-api-key", authenticationBody, http.StatusUnauthorized, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("with database url set and no api key in the request header", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "test-database-url")
		defer os.Unsetenv("DATABASE_URL")

		verify(t, "", authenticationBody, http.StatusUnauthorized, nil)
	})

}

func TestVerify_VerifyV1ExactSepolia(t *testing.T) {

	now := time.Now()

	validAfter := now.Add(-1 * time.Minute).Unix()
	validBefore := now.Add(1 * time.Minute).Unix()
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

	t.Run("invalid JSON body", func(t *testing.T) {
		verify(t, "", `{invalid json}`, http.StatusBadRequest, nil)
	})

	t.Run("missing payment payload", func(t *testing.T) {
		body := `{
			"x402Version": 1,
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
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
			"paymentRequirements": "paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
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
						"value": 1000,
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
						"value": 1000,
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
			"x402Version": 2,
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

	t.Run("authorization expired", func(t *testing.T) {
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
						"validBefore": ` + strconv.FormatInt(expiredBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if result.Valid {
				t.Errorf("expected authorization to be invalid (expired), but got valid=true")
			}
			if result.Reason != "authorization is expired" {
				t.Errorf("expected reason 'authorization is expired', got '%s'", result.Reason)
			}
		})
	})

	t.Run("authorization not valid yet", func(t *testing.T) {
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
						"validAfter": ` + strconv.FormatInt(futureAfter, 10) + `,
						"validBefore": ` + strconv.FormatInt(validBefore, 10) + `,
						"nonce": "` + validNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if result.Valid {
				t.Errorf("expected authorization to be invalid (not valid yet), but got valid=true")
			}
			if result.Reason != "authorization is not valid yet" {
				t.Errorf("expected reason 'authorization is not valid yet', got '%s'", result.Reason)
			}
		})
	})

	t.Run("value exceeds maximum", func(t *testing.T) {
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
						"value": 2000,
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
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if result.Valid {
				t.Errorf("expected authorization to be invalid (value exceeds maximum), but got valid=true")
			}
			if result.Reason != "authorization value exceeds the required maximum amount" {
				t.Errorf("expected reason 'authorization value exceeds the required maximum amount', got '%s'", result.Reason)
			}
		})
	})

	t.Run("address mismatch", func(t *testing.T) {
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
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if result.Valid {
				t.Errorf("expected authorization to be invalid (address mismatch), but got valid=true")
			}
			if result.Reason != "authorization to does not match required pay to address" {
				t.Errorf("expected reason 'authorization to does not match required pay to address', got '%s'", result.Reason)
			}
		})
	})

	t.Run("invalid nonce length", func(t *testing.T) {
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
						"nonce": "` + invalidNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
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

	t.Run("invalid nonce hex format", func(t *testing.T) {
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
						"nonce": "` + invalidHexNonce + `"
					}
				}
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia",
				"maxAmountRequired": 1000,
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

	t.Run("invalid signature length", func(t *testing.T) {
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

	t.Run("invalid signature hex format", func(t *testing.T) {
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

	t.Run("invalid signature - address mismatch", func(t *testing.T) {
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
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if result.Valid {
				t.Errorf("expected authorization to be invalid (signature address mismatch), but got valid=true. Signature was for %s but from was %s", signerAddress.Hex(), validAddress1)
			}
			if result.Reason != "invalid signature" {
				t.Errorf("expected reason 'invalid signature', got '%s'", result.Reason)
			}
		})
	})

	t.Run("valid signature - address matches", func(t *testing.T) {
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
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if !result.Valid {
				t.Errorf("expected authorization to be valid (signature matches), but got valid=false. Reason: %s", result.Reason)
			}
		})
	})

	t.Run("signature V value conversion 27", func(t *testing.T) {
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
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if !result.Valid {
				t.Errorf("expected signature to be valid, but got invalid. Reason: %s", result.Reason)
			}
		})
	})

	t.Run("signature V value conversion 28", func(t *testing.T) {
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
				"asset": "` + validAddress3 + `",
				"payTo": "` + validAddress2 + `",
				"extra": {
					"assetName": "Coin",
					"assetVersion": "1"
				}
			}
		}`
		verify(t, "", body, http.StatusOK, func(t *testing.T, body string) {
			var result struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("failed to decode response: %v. Body: %s", err, body)
			}
			if !result.Valid {
				t.Errorf("expected signature to be valid, but got invalid. Reason: %s", result.Reason)
			}
		})
	})
}
