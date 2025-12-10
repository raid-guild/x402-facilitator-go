package auth

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"os"

	"github.com/raid-guild/x402-facilitator-go/utils"
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

	// Check if the API key is required (dynamic key)
	if databaseURL != "" {

		// Check if the provided key is empty
		if providedKey == "" {
			return utils.NewStatusError(
				errors.New("unauthorized"),
				http.StatusUnauthorized,
			)
		}

		// Connect to the database
		db, err := sql.Open("postgres", databaseURL)
		if err != nil {
			return utils.NewStatusError(
				errors.New("failed to connect to database"),
				http.StatusInternalServerError,
			)
		}
		defer db.Close()

		// Check the API key exists in the database
		var apiKey string
		err = db.QueryRow(
			"SELECT api_key FROM users WHERE api_key = $1",
			providedKey,
		).Scan(&apiKey)

		// Check if the query returned a no rows error
		if err == sql.ErrNoRows {
			return utils.NewStatusError(
				errors.New("unauthorized"),
				http.StatusUnauthorized,
			)
		}

		// Check if the query returned a different error
		if err != nil {
			return utils.NewStatusError(
				errors.New("failed to get key from database"),
				http.StatusInternalServerError,
			)
		}
	}

	return nil
}
