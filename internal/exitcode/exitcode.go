// Package exitcode defines CTVault's process exit codes (spec §11.2) and a way
// to attach one to an error as it travels up to main.
package exitcode

import (
	"errors"
	"fmt"
)

// Exit codes from spec §11.2.
const (
	OK           = 0
	Error        = 1
	Usage        = 2
	DiskCap      = 3
	Volume       = 4
	Verification = 5
)

// CodedError carries an exit code alongside the error.
type CodedError struct {
	Code int
	Err  error
}

func (e *CodedError) Error() string { return e.Err.Error() }
func (e *CodedError) Unwrap() error { return e.Err }

// With attaches code to err. A nil err stays nil.
func With(code int, err error) error {
	if err == nil {
		return nil
	}
	return &CodedError{Code: code, Err: err}
}

// Withf formats a new error carrying code.
func Withf(code int, format string, args ...any) error {
	return &CodedError{Code: code, Err: fmt.Errorf(format, args...)}
}

// Of returns the exit code for err: OK for nil, the outermost attached code,
// or Error when none is attached.
func Of(err error) int {
	if err == nil {
		return OK
	}
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return Error
}
