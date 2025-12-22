package tests

import (
	"database/sql"
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

	t.Run("invalid_x402_version empty", func(t *testing.T) {
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
		verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_x402_version"))
	})

	t.Run("invalid_x402_version unsupported", func(t *testing.T) {
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
		verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_x402_version"))
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

			t.Run("invalid_payment_payload empty", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentRequirements": {
							"scheme": "exact",
							"network": "` + v.network + `"
						}
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentRequirements": {
							"scheme": "exact",
							"network": "` + v.network + `"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_payment_payload"))
			})

			t.Run("invalid_payment_payload invalid json", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": "invalid json",
						"paymentRequirements": {
							"scheme": "exact",
							"network": "` + v.network + `"
						}
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": "invalid json",
						"paymentRequirements": {
							"scheme": "exact",
							"network": "` + v.network + `"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_payment_payload"))
			})

			t.Run("invalid_payment_requirements empty", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"scheme": "exact",
							"network": "` + v.network + `"
						}
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_payment_requirements"))
			})

			t.Run("invalid_payment_requirements invalid json", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"scheme": "exact",
							"network": "` + v.network + `"
						},
						"paymentRequirements": "invalid json"
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							}
						},
						"paymentRequirements": "invalid json"
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_payment_requirements"))
			})

			t.Run("invalid_scheme empty", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"network": "` + v.network + `"
						},
						"paymentRequirements": {
							"network": "` + v.network + `"
						}
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"network": "` + v.network + `"
							}
						},
						"paymentRequirements": {
							"network": "` + v.network + `"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_scheme"))
			})

			t.Run("invalid_scheme unsupported", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "other",
								"network": "` + v.network + `"
							}
						},
						"paymentRequirements": {
							"scheme": "other",
							"network": "` + v.network + `"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_scheme"))
			})

			t.Run("invalid_network empty", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"scheme": "exact"
						},
						"paymentRequirements": {
							"scheme": "exact"
						}
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact"
							}
						},
						"paymentRequirements": {
							"scheme": "exact"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_network"))
			})

			t.Run("invalid_network unsupported", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "other"
							}
						},
						"paymentRequirements": {
							"scheme": "exact",
							"network": "other"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_network"))
			})

			t.Run("invalid_scheme_mismatch", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							}
						},
						"paymentRequirements": {
							"scheme": "other",
							"network": "` + v.network + `"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_scheme_mismatch"))
			})

			t.Run("invalid_network_mismatch", func(t *testing.T) {
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							}
						},
						"paymentRequirements": {
							"scheme": "exact",
							"network": "other"
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_network_mismatch"))
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

			t.Run("invalid_authorization_time_window equals", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_time_window"))
			})

			t.Run("invalid_authorization_time_window inverted", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_time_window"))
			})

			t.Run("invalid_authorization_valid_before expired", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_valid_before"))
			})

			t.Run("invalid_authorization_valid_after future", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_valid_after"))
			})

			t.Run("invalid_authorization_value not a number", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_value"))
			})

			t.Run("invalid_authorization_value negative", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_value_negative"))
			})

			t.Run("invalid_requirements_amount not a number", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "not-a-number",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_amount"))
			})

			t.Run("invalid_authorization_value_mismatch too low", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
							"maxAmountRequired": "2000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "2000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_value_mismatch"))
			})

			t.Run("invalid_authorization_value_mismatch too high", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_value_mismatch"))
			})

			t.Run("invalid_requirements_max_timeout empty", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_max_timeout"))
			})

			t.Run("invalid_requirements_max_timeout negative", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": -30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_max_timeout"))
			})

			t.Run("invalid_authorization_from_address not an address", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_from_address"))
			})

			t.Run("insufficient_funds", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "2000000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("insufficient_funds"))
			})

			t.Run("invalid_authorization_to_address not an address", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_to_address"))
			})

			t.Run("invalid_requirements_pay_to_address not an address", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "invalid-address",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_pay_to_address"))
			})

			t.Run("invalid_authorization_to_address_mismatch", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_to_address_mismatch"))
			})

			t.Run("invalid_authorization_nonce", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_nonce"))
			})

			t.Run("invalid_authorization_nonce_length", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_nonce_length"))
			})

			t.Run("invalid_requirements_asset not an address", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "invalid-address",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_asset"))
			})

			t.Run("invalid_requirements_extra_name empty", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_extra_name"))
			})

			t.Run("invalid_requirements_extra_version empty", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": ""
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_requirements_extra_version"))
			})

			t.Run("invalid_authorization_signature", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_signature"))
			})

			t.Run("invalid_authorization_signature_length", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "https://test.node")
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_signature_length"))
			})

			t.Run("invalid_authorization_sender_mismatch", func(t *testing.T) {
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
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectInvalidReason("invalid_authorization_sender_mismatch"))
			})

			t.Run("valid signature", func(t *testing.T) {
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
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectValid(signerAddress))
			})

			t.Run("valid signature V value 27", func(t *testing.T) {
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
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectValid(signerAddress))
			})

			t.Run("valid signature V value 28", func(t *testing.T) {
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
				body := ""
				switch v.x402Version {
				case "1":
					body = `{
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
				case "2":
					body = `{
						"x402Version": ` + v.x402Version + `,
						"paymentPayload": {
							"accepted": {
								"scheme": "exact",
								"network": "` + v.network + `"
							},
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
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				verify(t, "", body, http.StatusOK, expectValid(signerAddress))
			})

		})
	}

}
