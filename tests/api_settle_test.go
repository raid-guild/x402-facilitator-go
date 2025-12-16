package tests

import (
	"database/sql"
	"net/http"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSettle_Authentication(t *testing.T) {

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
		os.Setenv("STATIC_API_KEY", "valid-api-key")
		defer os.Unsetenv("STATIC_API_KEY")

		settle(t, "valid-api-key", body, http.StatusOK, nil)
	})

	t.Run("static api key required and invalid api key provided", func(t *testing.T) {
		os.Setenv("STATIC_API_KEY", "valid-api-key")
		defer os.Unsetenv("STATIC_API_KEY")

		settle(t, "invalid-api-key", body, http.StatusUnauthorized, nil)
	})

	t.Run("static api key required and no api key provided", func(t *testing.T) {
		os.Setenv("STATIC_API_KEY", "valid-api-key")
		defer os.Unsetenv("STATIC_API_KEY")

		settle(t, "", body, http.StatusUnauthorized, nil)
	})

	t.Run("database api key required and valid api key provided", func(t *testing.T) {
		mockDB, dsn, cleanup := setupMockDatabase(t, "settle-0")
		defer cleanup()

		os.Setenv("DATABASE_URL", dsn)
		defer os.Unsetenv("DATABASE_URL")

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

		os.Setenv("DATABASE_URL", dsn)
		defer os.Unsetenv("DATABASE_URL")

		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("invalid-api-key").
			WillReturnError(sql.ErrNoRows)

		settle(t, "invalid-api-key", body, http.StatusUnauthorized, nil)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("database api key required and no api key provided", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "test-database-url")
		defer os.Unsetenv("DATABASE_URL")

		settle(t, "", body, http.StatusUnauthorized, nil)
	})

}
