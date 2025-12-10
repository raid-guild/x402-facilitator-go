package tests

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	handler "github.com/raid-guild/x402-facilitator-go/api"
)

func TestSettle_NoAuthentication(t *testing.T) {

	t.Run("with no api key in the request header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settle", nil)
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("with irrelevant api key in the request header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settle", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

}

func TestSettle_StaticAPIKey(t *testing.T) {

	// Set up a test API key for authentication
	os.Setenv("STATIC_API_KEY", "valid-api-key")
	defer os.Unsetenv("STATIC_API_KEY")

	t.Run("with valid api key in the request header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settle", nil)
		req.Header.Set("X-API-Key", "valid-api-key")
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("with invalid api key in the request header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settle", nil)
		req.Header.Set("X-API-Key", "invalid-api-key")
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("with no api key in the request header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/settle", nil)
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

}

func TestSettle_DatabaseURL(t *testing.T) {

	t.Run("with valid api key in the request header", func(t *testing.T) {
		mockDB, _, cleanup := setupMockDatabase(t, "settle-0")
		defer cleanup()

		rows := sqlmock.NewRows([]string{"api_key"}).AddRow("valid-api-key")
		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("valid-api-key").
			WillReturnRows(rows)

		req := httptest.NewRequest("POST", "/settle", nil)
		req.Header.Set("X-API-Key", "valid-api-key")
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("with invalid api key in the request header", func(t *testing.T) {
		mockDB, _, cleanup := setupMockDatabase(t, "settle-1")
		defer cleanup()

		mockDB.ExpectQuery("SELECT api_key FROM users WHERE api_key = \\$1").
			WithArgs("invalid-api-key").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("POST", "/settle", nil)
		req.Header.Set("X-API-Key", "invalid-api-key")
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if err := mockDB.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("with no api key in the request header", func(t *testing.T) {
		os.Setenv("DATABASE_URL", "test-database-url")
		defer os.Unsetenv("DATABASE_URL")

		req := httptest.NewRequest("POST", "/settle", nil)
		w := httptest.NewRecorder()

		handler.Settle(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

}
