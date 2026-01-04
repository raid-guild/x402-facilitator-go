package utils

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	_ "github.com/lib/pq" // required for database/sql
)

var (
	// dbPoolCache stores the cached database connection pool (reused with warm instances).
	dbPoolCache = NewKeyedCache[*sql.DB]()
)

// GetDBPool gets a database connection pool, reusing the cached pool with warm instances.
// This function is declared as a variable so that it can be overridden in tests.
var GetDBPool = func(databaseURL string) (*sql.DB, error) {

	// Initialize or reuse the cached database connection pool
	return dbPoolCache.Get(databaseURL, func() (*sql.DB, error) {

		// Open a new database connection pool
		db, err := sql.Open("postgres", databaseURL)
		if err != nil {
			return nil, err
		}

		// SetMaxOpenConns limits concurrent connections to prevent database exhaustion
		// The default is unlimited, which can be problematic in serverless environments
		db.SetMaxOpenConns(10)

		// Return the database connection pool
		return db, nil
	})
}

// ResetDBPoolCache clears the cached database connection pool for the given URL.
// This is primarily useful for testing to ensure test isolation.
func ResetDBPoolCache(databaseURL string) {
	dbPoolCache.Reset(databaseURL)
}

var (
	// Dangerous keyword names
	dangerousKeywordNames = []string{
		"DROP",
		"ALTER",
		"CREATE",
		"TRUNCATE",
		"DELETE",
		"UPDATE",
		"INSERT",
		"EXEC",
		"EXECUTE",
		"UNION",
		"OR",
	}

	// Dangerous keyword patterns
	dangerousKeywordPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\bDROP\b`),
		regexp.MustCompile(`\bALTER\b`),
		regexp.MustCompile(`\bCREATE\b`),
		regexp.MustCompile(`\bTRUNCATE\b`),
		regexp.MustCompile(`\bDELETE\b`),
		regexp.MustCompile(`\bUPDATE\b`),
		regexp.MustCompile(`\bINSERT\b`),
		regexp.MustCompile(`\bEXEC\b`),
		regexp.MustCompile(`\bEXECUTE\b`),
		regexp.MustCompile(`\bUNION\b`),
		regexp.MustCompile(`\bOR\b`),
	}

	// Query validation patterns
	fromPattern           = regexp.MustCompile(`(?i)\s+FROM\s+`)
	wherePattern          = regexp.MustCompile(`(?i)\s+WHERE\s+`)
	invalidParamPattern   = regexp.MustCompile(`\$([2-9]|\d{2,})`)
	equalityPattern       = regexp.MustCompile(`\$1\s*=\s*\S|\S\s*=\s*\$1`)
	selfComparisonPattern = regexp.MustCompile(`\$1\s*=\s*\$1(?:\s|$|[^0-9$])`)
)

// ValidateDatabaseQuery validates that a database query is safe to use as a subquery.
func ValidateDatabaseQuery(query string) error {

	// Trim whitespace
	query = strings.TrimSpace(query)

	// Check query is not empty
	if query == "" {
		return errors.New("query cannot be empty")
	}

	// Check query length is not too long
	if len(query) > 100 {
		return errors.New("query exceeds maximum length")
	}

	// Convert to uppercase for keyword checking (preserve original)
	queryUpper := strings.ToUpper(query)

	// Define dangerous characters (checked as substrings)
	dangerousChars := []string{
		";",  // Statement separator
		"--", // Comments (inline)
		"/*", // Comments (multi-line start)
		"*/", // Comments (multi-line end)
	}

	// Check for dangerous characters
	for _, char := range dangerousChars {
		if strings.Contains(queryUpper, char) {
			return fmt.Errorf("query contains a dangerous character: %s", char)
		}
	}

	// Check for dangerous keywords (using pre-compiled patterns)
	for i, keywordPattern := range dangerousKeywordPatterns {
		if keywordPattern.MatchString(queryUpper) {
			return fmt.Errorf("query contains a dangerous keyword: %s", dangerousKeywordNames[i])
		}
	}

	// Ensure query starts with SELECT
	if !strings.HasPrefix(queryUpper, "SELECT") {
		return errors.New("query must start with SELECT")
	}

	// Ensure query contains a FROM clause (handle whitespace variants)
	if !fromPattern.MatchString(query) {
		return errors.New("query must contain a FROM clause")
	}

	// Ensure query contains a WHERE clause (handle whitespace variants)
	if !wherePattern.MatchString(query) {
		return errors.New("query must contain a WHERE clause")
	}

	// Ensure the WHERE clause rejects any parameter other than $1
	if invalidParamPattern.MatchString(query) {
		return errors.New("query must only use $1 as a parameter")
	}

	// Ensure the WHERE clause contains an equality comparison with $1
	if !equalityPattern.MatchString(query) {
		return errors.New("query must contain an equality comparison with $1")
	}

	// Ensure the WHERE clause does not contain $1 = $1 which would always be true
	if selfComparisonPattern.MatchString(query) {
		return errors.New("query must not contain $1 = $1")
	}

	return nil
}
