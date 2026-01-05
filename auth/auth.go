package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/raid-guild/x402-facilitator-go/utils"
)

var (
	// databaseQueryValidationCache stores the cached database query validation result (reused with warm instances).
	// The key is the database query string, and the value is the validation error (nil if valid).
	databaseQueryValidationCache = utils.NewKeyedCache[error]()
)

// Authenticate authenticates the request.
func Authenticate(r *http.Request) error {

	// Get the API key from the request header
	providedKey := r.Header.Get("X-API-Key")

	// Get the static API key from the environment
	staticKey := os.Getenv("STATIC_API_KEY")

	// Get the database URL from the environment
	databaseURL := os.Getenv("DATABASE_URL")

	// Check if the environment is misconfigured
	if staticKey != "" && databaseURL != "" {
		return utils.NewStatusError(
			errors.New("both static API key and database URL are set"),
			http.StatusInternalServerError,
		)
	}

	// Check if the API key is required (static key)
	if staticKey != "" {

		// Check if the provided key does not match the static key
		if subtle.ConstantTimeCompare([]byte(providedKey), []byte(staticKey)) != 1 {
			return utils.NewStatusError(
				errors.New("unauthorized"),
				http.StatusUnauthorized,
			)
		}
	}

	// Check if the API key is required (database key)
	if databaseURL != "" {

		// Check if the provided key is empty
		if providedKey == "" {
			return utils.NewStatusError(
				errors.New("unauthorized"),
				http.StatusUnauthorized,
			)
		}

		// Get the database query from the environment
		databaseQuery := os.Getenv("DATABASE_QUERY")

		// Validate the custom database query if it is set
		if databaseQuery != "" {

			// Get the cached validation result (reused with warm instances)
			validationErr, _ := databaseQueryValidationCache.Get(databaseQuery, func() (error, error) {
				// Validate the database query
				return utils.ValidateDatabaseQuery(databaseQuery), nil
			})

			// Check if the validation returned an error
			if validationErr != nil {
				return utils.NewStatusError(
					errors.New("invalid database query"),
					http.StatusInternalServerError,
				)
			}
		}

		// Use the default database query if custom is not set
		if databaseQuery == "" {
			databaseQuery = "SELECT 1 FROM users WHERE api_key = $1"
		}

		// Set the destination for the query
		var exists bool

		// Wrap the database query in an exists query
		existsQuery := fmt.Sprintf("SELECT EXISTS(%s)", databaseQuery)

		// Get the database connection pool (reused with warm instances)
		db, err := utils.GetDBPool(databaseURL)
		if err != nil {
			return utils.NewStatusError(
				errors.New("failed to connect to database"),
				http.StatusInternalServerError,
			)
		}

		// Execute the query and scan the result
		err = db.QueryRow(existsQuery, providedKey).Scan(&exists)

		// Check if the query returned an error
		if err != nil {
			return utils.NewStatusError(
				errors.New("failed to get key from database"),
				http.StatusInternalServerError,
			)
		}

		// Check if the API key does not exist
		if !exists {
			return utils.NewStatusError(
				errors.New("unauthorized"),
				http.StatusUnauthorized,
			)
		}
	}

	return nil
}
