package utils

// StatusError is a custom error type that includes a status code.
type StatusError struct {
	error
	status int
}

// Status returns the status code of the error.
func (se StatusError) Status() int {
	return se.status
}

// NewStatusError creates a new StatusError.
func NewStatusError(err error, s int) error {
	return StatusError{error: err, status: s}
}
