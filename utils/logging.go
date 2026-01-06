package utils

import (
	"log"
)

// LogInternalServerError logs an internal server error.
func LogInternalServerError(err error) {
	if err == nil {
		return
	}
	log.Printf("internal server error: %v", err)
}

// LogWriteError logs an error that occurs after HTTP headers have been written.
func LogWriteError(err error) {
	if err == nil {
		return
	}
	log.Printf("failed to write response: %v", err)
}
