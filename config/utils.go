package config

import (
	"fmt"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.Trim(e, " "))
	}
	return
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func or(pointers ...*int) *int {
	for _, p := range pointers {
		if p != nil {
			return p
		}
	}
	return pointers[len(pointers)-1]
}
