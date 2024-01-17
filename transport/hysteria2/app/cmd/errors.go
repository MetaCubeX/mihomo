package cmd

import (
	"fmt"
)

type configError struct {
	Field string
	Err   error
}

func (e configError) Error() string {
	return fmt.Sprintf("invalid config: %s: %s", e.Field, e.Err)
}

func (e configError) Unwrap() error {
	return e.Err
}
