package tests

import (
	"database/sql"
	"os"
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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

	os.Setenv("DATABASE_URL", dsn)
	cleanup := func() {
		db.Close()
		os.Unsetenv("DATABASE_URL")
	}

	return mock, dsn, cleanup
}
