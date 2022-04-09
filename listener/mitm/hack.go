package mitm

import (
	_ "net/http"
	_ "unsafe"
)

//go:linkname validMethod net/http.validMethod
func validMethod(method string) bool
