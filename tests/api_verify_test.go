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

func TestVerify_Compatibility(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	t.Run("invalid body JSON", func(t *testing.T) {
		verify(t, "", `{invalid json}`, http.StatusBadRequest, nil)
	})

	t.Run("missing x402 version", func(t *testing.T) {
		body := `{
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia"
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia"
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
			if response.InvalidReason != "invalid_x402_version" {
				t.Errorf("expected invalid reason 'invalid_x402_version', got '%s'", response.InvalidReason)
			}
		})
	})

	t.Run("unsupported x402 version", func(t *testing.T) {
		body := `{
			"x402Version": 100,
			"paymentPayload": {
				"scheme": "exact",
				"network": "sepolia"
			},
			"paymentRequirements": {
				"scheme": "exact",
				"network": "sepolia"
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
			if response.InvalidReason != "invalid_x402_version" {
				t.Errorf("expected invalid reason 'invalid_x402_version', got '%s'", response.InvalidReason)
			}
		})
	})

	versions := []struct {
		name        string
		x402Version string
		network     string
	}{
		{
			name:        "v1 sepolia",
			x402Version: "1",
			network:     "sepolia",
		},
		{
			name:        "v1 base sepolia",
			x402Version: "1",
			network:     "base-sepolia",
		},
		{
			name:        "v2 sepolia",
			x402Version: "2",
			network:     "eip155:11155111",
		},
		{
			name:        "v2 base sepolia",
			x402Version: "2",
			network:     "eip155:84532",
		},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {

			t.Run("missing payment payload", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `"
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
					if response.InvalidReason != "invalid_payment_payload" {
						t.Errorf("expected invalid reason 'invalid_payment_payload', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("invalid payment payload JSON", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": "invalid json",
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `"
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
					if response.InvalidReason != "invalid_payment_payload" {
						t.Errorf("expected invalid reason 'invalid_payment_payload', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("missing payment requirements", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `"
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
					if response.InvalidReason != "invalid_payment_requirements" {
						t.Errorf("expected invalid reason 'invalid_payment_requirements', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("invalid payment requirements JSON", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `"
					},
					"paymentRequirements": "invalid json"
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
					if response.InvalidReason != "invalid_payment_requirements" {
						t.Errorf("expected invalid reason 'invalid_payment_requirements', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("unsupported scheme", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "other",
						"network": "` + v.network + `"
					},
					"paymentRequirements": {
						"scheme": "other",
						"network": "` + v.network + `"
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
					if response.InvalidReason != "invalid_scheme" {
						t.Errorf("expected invalid reason 'invalid_scheme', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("unsupported network", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "other"
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "other"
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
					if response.InvalidReason != "invalid_network" {
						t.Errorf("expected invalid reason 'invalid_network', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("scheme mismatch", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `"
					},
					"paymentRequirements": {
						"scheme": "other",
						"network": "` + v.network + `"
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
					if response.InvalidReason != "invalid_scheme_mismatch" {
						t.Errorf("expected invalid reason 'invalid_scheme_mismatch', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("network mismatch", func(t *testing.T) {
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `"
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "other"
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
					if response.InvalidReason != "invalid_network_mismatch" {
						t.Errorf("expected invalid reason 'invalid_network_mismatch', got '%s'", response.InvalidReason)
					}
				})
			})

		})
	}

}

func TestVerify_VerifyExact(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	now := time.Now()

	validAfter := strconv.FormatInt(now.Add(-2*time.Minute).Unix(), 10)
	validBefore := strconv.FormatInt(now.Add(2*time.Minute).Unix(), 10)
	expiredBefore := strconv.FormatInt(now.Add(-1*time.Minute).Unix(), 10)
	futureAfter := strconv.FormatInt(now.Add(1*time.Minute).Unix(), 10)

	validNonce := "0x" + strings.Repeat("00", 32)
	invalidNonce := "0x" + strings.Repeat("00", 33)
	invalidHexNonce := "0xZZ" + strings.Repeat("00", 30)

	validAddress1 := "0x0000000000000000000000000000000000000001"
	validAddress2 := "0x0000000000000000000000000000000000000002"
	validAddress3 := "0x0000000000000000000000000000000000000003"

	validSignature := "0x" + strings.Repeat("00", 65)
	invalidSignature := "0x" + strings.Repeat("00", 64)
	invalidHexSignature := "0xZZ" + strings.Repeat("00", 63)

	versions := []struct {
		name        string
		x402Version string
		network     string
		rpcEnvVar   string
		chainID     int64
	}{
		{
			name:        "v1 sepolia",
			x402Version: "1",
			network:     "sepolia",
			rpcEnvVar:   "RPC_URL_SEPOLIA",
			chainID:     11155111,
		},
		{
			name:        "v1 base sepolia",
			x402Version: "1",
			network:     "base-sepolia",
			rpcEnvVar:   "RPC_URL_BASE_SEPOLIA",
			chainID:     84532,
		},
		{
			name:        "v2 sepolia",
			x402Version: "2",
			network:     "eip155:11155111",
			rpcEnvVar:   "RPC_URL_SEPOLIA",
			chainID:     11155111,
		},
		{
			name:        "v2 base sepolia",
			x402Version: "2",
			network:     "eip155:84532",
			rpcEnvVar:   "RPC_URL_BASE_SEPOLIA",
			chainID:     84532,
		},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {

			t.Run("authorization time window invalid equals", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validAfter + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_time_window" {
						t.Errorf("expected invalid reason 'invalid_authorization_time_window', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization time window invalid inverted", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validBefore + `",
								"validBefore": "` + validAfter + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_time_window" {
						t.Errorf("expected invalid reason 'invalid_authorization_time_window', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization valid before expired", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + expiredBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_valid_before" {
						t.Errorf("expected invalid reason 'invalid_authorization_valid_before', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization valid after future", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + futureAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_valid_after" {
						t.Errorf("expected invalid reason 'invalid_authorization_valid_after', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization value not a number", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "not-a-number",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_value" {
						t.Errorf("expected invalid reason 'invalid_authorization_value', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization value negative", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "-1",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_value_negative" {
						t.Errorf("expected invalid reason 'invalid_authorization_value_negative', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements max amount not a number", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "not-a-number",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_requirements_max_amount" {
						t.Errorf("expected invalid reason 'invalid_requirements_max_amount', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization value exceeds", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "2000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_value_exceeded" {
						t.Errorf("expected invalid reason 'invalid_authorization_value_exceeded', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements max timeout missing", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_requirements_max_timeout" {
						t.Errorf("expected invalid reason 'invalid_requirements_max_timeout', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements max timeout negative", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": -30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_requirements_max_timeout" {
						t.Errorf("expected invalid reason 'invalid_requirements_max_timeout', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization from invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "invalid-address",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_from_address" {
						t.Errorf("expected invalid reason 'invalid_authorization_from_address', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization from insufficient funds", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "2000000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "2000000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "insufficient_funds" {
						t.Errorf("expected invalid reason 'insufficient_funds', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization to invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "invalid-address",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_to_address" {
						t.Errorf("expected invalid reason 'invalid_authorization_to_address', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements pay to invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "invalid-address",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_requirements_pay_to_address" {
						t.Errorf("expected invalid reason 'invalid_requirements_pay_to_address', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization to address mismatch", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress1 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_to_address_mismatch" {
						t.Errorf("expected invalid reason 'invalid_authorization_to_address_mismatch', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization nonce hex invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + invalidHexNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_nonce" {
						t.Errorf("expected invalid reason 'invalid_authorization_nonce', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("authorization nonce length invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + invalidNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_nonce_length" {
						t.Errorf("expected invalid reason 'invalid_authorization_nonce_length', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements asset invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "invalid-address",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_requirements_asset" {
						t.Errorf("expected invalid reason 'invalid_requirements_asset', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements extra name empty", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "",
							"version": "1"
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
					if response.InvalidReason != "invalid_requirements_extra_name" {
						t.Errorf("expected invalid reason 'invalid_requirements_extra_name', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("requirements extra version empty", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + validSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": ""
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
					if response.InvalidReason != "invalid_requirements_extra_version" {
						t.Errorf("expected invalid reason 'invalid_requirements_extra_version', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("signature hex invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + invalidHexSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_signature" {
						t.Errorf("expected invalid reason 'invalid_authorization_signature', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("signature length invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + invalidSignature + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_signature_length" {
						t.Errorf("expected invalid reason 'invalid_authorization_signature_length', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("signature address mismatch", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				sig, _, err := generateEIP712Signature(
					validAddress2,
					validAddress3,
					1000,
					validAfter,
					validBefore,
					validNonce,
					"Coin",
					"1",
					v.chainID,
				)
				if err != nil {
					t.Fatalf("failed to generate signature: %v", err)
				}
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + sig + `",
							"authorization": {
								"from": "` + validAddress1 + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
					if response.InvalidReason != "invalid_authorization_sender_mismatch" {
						t.Errorf("expected invalid reason 'invalid_authorization_sender_mismatch', got '%s'", response.InvalidReason)
					}
				})
			})

			t.Run("signature address confirmed", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				sig, signerAddress, err := generateEIP712Signature(
					validAddress2,
					validAddress3,
					1000,
					validAfter,
					validBefore,
					validNonce,
					"Coin",
					"1",
					v.chainID,
				)
				if err != nil {
					t.Fatalf("failed to generate signature: %v", err)
				}
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + sig + `",
							"authorization": {
								"from": "` + signerAddress.Hex() + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
				t.Setenv(v.rpcEnvVar, "https://test.node")
				sig, signerAddress, err := generateEIP712SignatureWithLegacyV(
					validAddress2,
					validAddress3,
					1000,
					validAfter,
					validBefore,
					validNonce,
					"Coin",
					"1",
					v.chainID,
					27,
				)
				if err != nil {
					t.Fatalf("failed to generate signature: %v", err)
				}
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + sig + `",
							"authorization": {
								"from": "` + signerAddress.Hex() + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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
				t.Setenv(v.rpcEnvVar, "https://test.node")
				sig, signerAddress, err := generateEIP712SignatureWithLegacyV(
					validAddress2,
					validAddress3,
					1000,
					validAfter,
					validBefore,
					validNonce,
					"Coin",
					"1",
					v.chainID,
					28,
				)
				if err != nil {
					t.Fatalf("failed to generate signature: %v", err)
				}
				body := `{
					"x402Version": ` + v.x402Version + `,
					"paymentPayload": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"payload": {
							"signature": "` + sig + `",
							"authorization": {
								"from": "` + signerAddress.Hex() + `",
								"to": "` + validAddress2 + `",
								"value": "1000",
								"validAfter": "` + validAfter + `",
								"validBefore": "` + validBefore + `",
								"nonce": "` + validNonce + `"
							}
						}
					},
					"paymentRequirements": {
						"scheme": "exact",
						"network": "` + v.network + `",
						"maxAmountRequired": "1000",
						"maxTimeoutSeconds": 30,
						"asset": "` + validAddress3 + `",
						"payTo": "` + validAddress2 + `",
						"extra": {
							"name": "Coin",
							"version": "1"
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

		})
	}

}
