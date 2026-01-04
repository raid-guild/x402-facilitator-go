package tests

import (
	"strings"
	"testing"

	"github.com/raid-guild/x402-facilitator-go/utils"
)

func TestValidateDatabaseQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
		errMsg  string
	}{
		// Valid queries
		{
			name:    "valid default query",
			query:   "SELECT 1 FROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "valid query with different table",
			query:   "SELECT 1 FROM organizations WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "valid query with different column",
			query:   "SELECT id FROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "valid query with multiple columns",
			query:   "SELECT id, name FROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "valid query with tabs",
			query:   "SELECT 1\tFROM\tusers\tWHERE\tapi_key\t=\t$1",
			wantErr: false,
		},
		{
			name:    "valid query with newlines",
			query:   "SELECT 1\nFROM users\nWHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "valid query with mixed whitespace",
			query:   "SELECT 1\nFROM\tusers WHERE\napi_key = $1",
			wantErr: false,
		},
		{
			name:    "valid query with AND for additional conditions",
			query:   "SELECT 1 FROM users WHERE api_key = $1 AND status = 'active'",
			wantErr: false,
		},
		{
			name:    "valid query with multiple AND conditions",
			query:   "SELECT 1 FROM users WHERE api_key = $1 AND status = 'active' AND role = 'admin'",
			wantErr: false,
		},
		{
			name:    "query starting with lowercase select",
			query:   "select 1 FROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "keyword in table name should not match",
			query:   "SELECT 1 FROM droptable WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "keyword in column name should not match",
			query:   "SELECT 1 FROM users WHERE dropcolumn = $1",
			wantErr: false,
		},
		{
			name:    "query with FROM using newline",
			query:   "SELECT 1\nFROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "query with FROM using tab",
			query:   "SELECT 1\tFROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "query with FROM using multiple spaces",
			query:   "SELECT 1  FROM users WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "query with WHERE using newline",
			query:   "SELECT 1 FROM users\nWHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "query with WHERE using tab",
			query:   "SELECT 1 FROM users\tWHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "query with WHERE using multiple spaces",
			query:   "SELECT 1 FROM users  WHERE api_key = $1",
			wantErr: false,
		},
		{
			name:    "query with $1 on left side of equality",
			query:   "SELECT 1 FROM users WHERE $1 = api_key",
			wantErr: false,
		},
		{
			name:    "query with equality and spaces",
			query:   "SELECT 1 FROM users WHERE api_key  =  $1",
			wantErr: false,
		},
		{
			name:    "query with equality and newline",
			query:   "SELECT 1 FROM users WHERE api_key\n=\n$1",
			wantErr: false,
		},
		{
			name:    "query with equality and tab",
			query:   "SELECT 1 FROM users WHERE api_key\t=\t$1",
			wantErr: false,
		},
		{
			name:    "query with multiple equals signs",
			query:   "SELECT 1 FROM users WHERE api_key = $1 AND status = 'active'",
			wantErr: false,
		},
		// Empty string
		{
			name:    "empty query",
			query:   "",
			wantErr: true,
			errMsg:  "query cannot be empty",
		},
		{
			name:    "whitespace only",
			query:   "   ",
			wantErr: true,
			errMsg:  "query cannot be empty",
		},
		// Query length
		{
			name:    "query too long",
			query:   strings.Repeat("SELECT 1 FROM users WHERE api_key = $1 ", 10),
			wantErr: true,
			errMsg:  "query exceeds maximum length",
		},
		// Dangerous characters
		{
			name:    "query with semicolon",
			query:   "SELECT 1 FROM users WHERE api_key = $1; DROP TABLE users",
			wantErr: true,
			errMsg:  "query contains a dangerous character: ;",
		},
		{
			name:    "query with inline comment",
			query:   "SELECT 1 FROM users WHERE api_key = $1 -- comment",
			wantErr: true,
			errMsg:  "query contains a dangerous character: --",
		},
		{
			name:    "query with multi-line comment start",
			query:   "SELECT 1 FROM users WHERE api_key = $1 /* comment",
			wantErr: true,
			errMsg:  "query contains a dangerous character: /*",
		},
		{
			name:    "query with multi-line comment end",
			query:   "SELECT 1 FROM users WHERE api_key = $1 */",
			wantErr: true,
			errMsg:  "query contains a dangerous character: */",
		},
		// Dangerous keywords
		{
			name:    "query with DROP",
			query:   "SELECT 1 FROM users WHERE api_key = $1 DROP TABLE users",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: DROP",
		},
		{
			name:    "query with ALTER",
			query:   "SELECT 1 FROM users WHERE api_key = $1 ALTER TABLE",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: ALTER",
		},
		{
			name:    "query with CREATE",
			query:   "SELECT 1 FROM users WHERE api_key = $1 CREATE TABLE",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: CREATE",
		},
		{
			name:    "query with TRUNCATE",
			query:   "SELECT 1 FROM users WHERE api_key = $1 TRUNCATE",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: TRUNCATE",
		},
		{
			name:    "query with DELETE",
			query:   "SELECT 1 FROM users WHERE api_key = $1 DELETE FROM",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: DELETE",
		},
		{
			name:    "query with UPDATE",
			query:   "SELECT 1 FROM users WHERE api_key = $1 UPDATE users",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: UPDATE",
		},
		{
			name:    "query with INSERT",
			query:   "SELECT 1 FROM users WHERE api_key = $1 INSERT INTO",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: INSERT",
		},
		{
			name:    "query with UNION",
			query:   "SELECT 1 FROM users WHERE api_key = $1 UNION SELECT",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: UNION",
		},
		{
			name:    "query with EXEC",
			query:   "SELECT 1 FROM users WHERE api_key = $1 EXEC",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: EXEC",
		},
		{
			name:    "query with EXECUTE",
			query:   "SELECT 1 FROM users WHERE api_key = $1 EXECUTE",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: EXECUTE",
		},
		{
			name:    "query with OR ",
			query:   "SELECT 1 FROM users WHERE api_key = $1 OR status = 'active'",
			wantErr: true,
			errMsg:  "query contains a dangerous keyword: OR",
		},
		// Starts with SELECT
		{
			name:    "query not starting with SELECT",
			query:   "FROM users WHERE api_key = $1",
			wantErr: true,
			errMsg:  "query must start with SELECT",
		},
		// Contains FROM clause
		{
			name:    "query missing FROM",
			query:   "SELECT 1 WHERE api_key = $1",
			wantErr: true,
			errMsg:  "query must contain a FROM clause",
		},
		{
			name:    "query with FROM but no space before",
			query:   "SELECT 1FROM users WHERE api_key = $1",
			wantErr: true,
			errMsg:  "query must contain a FROM clause",
		},
		{
			name:    "query with FROM but no space after",
			query:   "SELECT 1 FROMusers WHERE api_key = $1",
			wantErr: true,
			errMsg:  "query must contain a FROM clause",
		},
		// Contains WHERE clause
		{
			name:    "query missing WHERE",
			query:   "SELECT 1 FROM users",
			wantErr: true,
			errMsg:  "query must contain a WHERE clause",
		},
		{
			name:    "query with WHERE but no space before",
			query:   "SELECT 1 FROM usersWHERE api_key = $1",
			wantErr: true,
			errMsg:  "query must contain a WHERE clause",
		},
		{
			name:    "query with WHERE but no space after",
			query:   "SELECT 1 FROM users WHEREapi_key = $1",
			wantErr: true,
			errMsg:  "query must contain a WHERE clause",
		},
		// Only $1 allowed
		{
			name:    "query with $2 should be rejected",
			query:   "SELECT 1 FROM users WHERE id = $2",
			wantErr: true,
			errMsg:  "query must only use $1 as a parameter",
		},
		{
			name:    "query with $10 should be rejected",
			query:   "SELECT 1 FROM users WHERE id = $10",
			wantErr: true,
			errMsg:  "query must only use $1 as a parameter",
		},
		{
			name:    "query with $11 should be rejected",
			query:   "SELECT 1 FROM users WHERE id = $11",
			wantErr: true,
			errMsg:  "query must only use $1 as a parameter",
		},
		{
			name:    "query with $1 and $2 should be rejected",
			query:   "SELECT 1 FROM users WHERE api_key = $1 AND status = $2",
			wantErr: true,
			errMsg:  "query must only use $1 as a parameter",
		},
		{
			name:    "query with $2 and $1 should be rejected",
			query:   "SELECT 1 FROM users WHERE status = $2 AND api_key = $1",
			wantErr: true,
			errMsg:  "query must only use $1 as a parameter",
		},
		// Equality comparison
		{
			name:    "query missing equality comparison",
			query:   "SELECT 1 FROM users WHERE id > $1",
			wantErr: true,
			errMsg:  "query must contain an equality comparison with $1",
		},
		{
			name:    "query with inequality only",
			query:   "SELECT 1 FROM users WHERE id < $1",
			wantErr: true,
			errMsg:  "query must contain an equality comparison with $1",
		},
		{
			name:    "query with IS NOT NULL",
			query:   "SELECT 1 FROM users WHERE $1 IS NOT NULL",
			wantErr: true,
			errMsg:  "query must contain an equality comparison with $1",
		},
		{
			name:    "query with equality but no $1",
			query:   "SELECT 1 FROM users WHERE api_key = 'test'",
			wantErr: true,
			errMsg:  "query must contain an equality comparison with $1",
		},
		{
			name:    "query with $1 but no equality",
			query:   "SELECT 1 FROM users WHERE api_key LIKE $1",
			wantErr: true,
			errMsg:  "query must contain an equality comparison with $1",
		},
		// Explicit $1 = $1
		{
			name:    "query with self comparison",
			query:   "SELECT 1 FROM users WHERE $1 = $1",
			wantErr: true,
			errMsg:  "query must not contain $1 = $1",
		},
		{
			name:    "query with self comparison without spaces",
			query:   "SELECT 1 FROM users WHERE $1=$1",
			wantErr: true,
			errMsg:  "query must not contain $1 = $1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidateDatabaseQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDatabaseQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateDatabaseQuery() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}
