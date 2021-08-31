package http

import (
	"bufio"
	"net/http"
	_ "unsafe"
)

//go:linkname ReadRequest net/http.readRequest
func ReadRequest(b *bufio.Reader) (req *http.Request, err error)
