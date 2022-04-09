package rewrites

import (
	"regexp"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

func ParseRewrite(line string) (C.Rewrite, error) {
	url, others, found := strings.Cut(strings.TrimSpace(line), "url")
	if !found {
		return nil, errInvalid
	}

	var (
		urlRegx     *regexp.Regexp
		ruleType    *C.RewriteType
		ruleRegx    *regexp.Regexp
		rulePayload string

		err error
	)

	urlRegx, err = regexp.Compile(strings.Trim(url, " "))
	if err != nil {
		return nil, err
	}

	others = strings.Trim(others, " ")
	first := strings.Split(others, " ")[0]
	for k, v := range C.RewriteTypeMapping {
		if k == others {
			ruleType = &v
			break
		}

		if k != first {
			continue
		}

		rs := trimArr(strings.Split(others, k))
		l := len(rs)
		if l > 2 {
			continue
		}

		if l == 1 {
			ruleType = &v
			rulePayload = rs[0]
			break
		} else {
			ruleRegx, err = regexp.Compile(rs[0])
			if err != nil {
				return nil, err
			}

			ruleType = &v
			rulePayload = rs[1]
			break
		}
	}

	if ruleType == nil {
		return nil, errInvalid
	}

	return NewRewriteRule(urlRegx, *ruleType, ruleRegx, rulePayload), nil
}

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		if s := strings.Trim(e, " "); s != "" {
			r = append(r, s)
		}
	}
	return
}
