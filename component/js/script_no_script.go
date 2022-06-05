//go:build no_script

package js

import "fmt"

func NewJS(name, code string) error {
	fmt.Errorf("unsupported script on the build")
}

func Run(name string, args map[string]any, callback func(any, error)) {
}
