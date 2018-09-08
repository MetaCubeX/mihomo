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

func parseOptions(startIdx int, params ...string) map[string]string {
	mapping := make(map[string]string)
	if len(params) <= startIdx {
		return mapping
	}

	for _, option := range params[startIdx:] {
		pair := strings.SplitN(option, "=", 2)
		if len(pair) != 2 {
			continue
		}

		mapping[strings.Trim(pair[0], " ")] = strings.Trim(pair[1], " ")
	}
	return mapping
}
