package rewrites

import (
	regexp "github.com/dlclark/regexp2"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

func ParseRewrite(line RawMitmRule) (C.Rewrite, error) {
	var (
		urlRegx     *regexp.Regexp
		ruleType    *C.RewriteType
		ruleRegx    *regexp.Regexp
		rulePayload string

		err error
	)

	url := line.Url
	urlRegx, err = regexp.Compile(strings.Trim(url, " "), regexp.None)
	if err != nil {
		return nil, err
	}

	ruleType = &line.Action
	switch *ruleType {
	case C.Mitm302, C.Mitm307:
		{
			rulePayload = line.New
			break
		}
	case C.MitmRequestHeader, C.MitmRequestBody, C.MitmResponseHeader, C.MitmResponseBody:
		{
			var old string
			if line.Old == nil {
				old = ".*"
			} else {
				old = *line.Old
			}

			re, err := regexp.Compile(old, regexp.Singleline)
			if err != nil {
				return nil, err
			}
			ruleRegx = re

			rulePayload = line.New
		}
	}

	return NewRewriteRule(urlRegx, *ruleType, ruleRegx, rulePayload), nil
}
