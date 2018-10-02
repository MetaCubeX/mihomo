package config

import (
	"fmt"
	"strings"
)

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.Trim(e, " "))
	}
	return
}

func genAddr(port int, allowLan bool) string {
	if allowLan {
		return fmt.Sprintf(":%d", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func or(pointers ...*int) *int {
	for _, p := range pointers {
		if p != nil {
			return p
		}
	}
	return pointers[len(pointers)-1]
}
