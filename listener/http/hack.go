package http

import (
	"bufio"
	_ "unsafe"

	"github.com/metacubex/http"
)

//go:linkname ReadRequest github.com/metacubex/http.readRequest
func ReadRequest(b *bufio.Reader) (req *http.Request, err error)
