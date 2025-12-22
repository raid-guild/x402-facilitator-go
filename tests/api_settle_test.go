package tests

import (
	"database/sql"
	"encoding/hex"
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

	t.Setenv("RPC_URL_SEPOLIA", "rpc-url")
	t.Setenv("PRIVATE_KEY", "private-key")

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

func TestSettle_Compatibility(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	t.Run("invalid body JSON", func(t *testing.T) {
		settle(t, "", `{invalid json}`, http.StatusBadRequest, nil)
	})

	t.Run("invalid_x402_version empty", func(t *testing.T) {
		body := `{
			"paymentPayload": {},
			"paymentRequirements": {}
		}`
		settle(t, "", body, http.StatusOK, expectErrorReason("invalid_x402_version"))
	})

	t.Run("invalid_x402_version unsupported", func(t *testing.T) {
		body := `{
			"x402Version": 100,
			"paymentPayload": {},
			"paymentRequirements": {}
		}`
		settle(t, "", body, http.StatusOK, expectErrorReason("invalid_x402_version"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_payment_payload"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_payment_payload"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_payment_requirements"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_payment_requirements"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_scheme"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_scheme"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_network"))
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
				settle(t, "", body, http.StatusOK, expectErrorReason("invalid_network"))
			})

		})
	}

}

func TestSettle_SettleExact(t *testing.T) {

	setupMockEthClient(t) // do not make any actual RPC calls

	validAddress1 := "0x0000000000000000000000000000000000000001"
	validAddress2 := "0x0000000000000000000000000000000000000002"
	validAddress3 := "0x0000000000000000000000000000000000000003"

	now := time.Now()

	validAfter := strconv.FormatInt(now.Add(-2*time.Minute).Unix(), 10)
	validBefore := strconv.FormatInt(now.Add(2*time.Minute).Unix(), 10)

	validNonce := "0x" + strings.Repeat("00", 32)

	validSignature := "0x" + strings.Repeat("00", 65)

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	privateKeyHex := "0x" + hex.EncodeToString(crypto.FromECDSA(privateKey))

	versions := []struct {
		name        string
		x402Version string
		network     string
		rpcEnvVar   string
	}{
		{
			name:        "v1 sepolia",
			x402Version: "1",
			network:     "sepolia",
			rpcEnvVar:   "RPC_URL_SEPOLIA",
		},
		{
			name:        "v1 base sepolia",
			x402Version: "1",
			network:     "base-sepolia",
			rpcEnvVar:   "RPC_URL_BASE_SEPOLIA",
		},
		{
			name:        "v2 sepolia",
			x402Version: "2",
			network:     "eip155:11155111",
			rpcEnvVar:   "RPC_URL_SEPOLIA",
		},
		{
			name:        "v2 base sepolia",
			x402Version: "2",
			network:     "eip155:84532",
			rpcEnvVar:   "RPC_URL_BASE_SEPOLIA",
		},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {

			t.Run(v.rpcEnvVar+" not set", func(t *testing.T) {
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"maxAmountRequired": "1000",
							"maxTimeoutSeconds": 30,
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				settle(t, "", body, http.StatusInternalServerError, nil)
			})

			t.Run("PRIVATE_KEY not set", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "rpc-url")
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"maxAmountRequired": "1000",
							"maxTimeoutSeconds": 30,
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				settle(t, "", body, http.StatusInternalServerError, nil)
			})

			t.Run("PRIVATE_KEY invalid", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "rpc-url")
				t.Setenv("PRIVATE_KEY", "invalid-hex-key")
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"maxAmountRequired": "1000",
							"maxTimeoutSeconds": 30,
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				settle(t, "", body, http.StatusInternalServerError, nil)
			})

			t.Run("success", func(t *testing.T) {
				t.Setenv(v.rpcEnvVar, "rpc-url")
				t.Setenv("PRIVATE_KEY", privateKeyHex)
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"maxAmountRequired": "1000",
							"maxTimeoutSeconds": 30,
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
							"asset": "` + validAddress3 + `",
							"payTo": "` + validAddress2 + `",
							"amount": "1000",
							"maxTimeoutSeconds": 30,
							"extra": {
								"name": "Coin",
								"version": "1"
							}
						}
					}`
				default:
					t.Fatalf("unexpected x402 version: %s", v.x402Version)
				}
				settle(t, "", body, http.StatusOK, expectSuccess())
			})

		})
	}

}
