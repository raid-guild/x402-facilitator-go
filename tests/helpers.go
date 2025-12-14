package tests

import (
	"database/sql"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	handler "github.com/raid-guild/x402-facilitator-go/api"
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
