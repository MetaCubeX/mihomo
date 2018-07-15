package hub

import (
	"github.com/Dreamacro/clash/proxy"
	T "github.com/Dreamacro/clash/tunnel"
)

var (
	tunnel   = T.GetInstance()
	listener = proxy.Instance()
)

type Error struct {
	Error string `json:"error"`
}

type Errors struct {
	Errors map[string]string `json:"errors"`
}

func formatErrors(errorsMap map[string]error) (bool, Errors) {
	errors := make(map[string]string)
	hasError := false
	for key, err := range errorsMap {
		if err != nil {
			errors[key] = err.Error()
			hasError = true
		}
	}
	return hasError, Errors{Errors: errors}
}
