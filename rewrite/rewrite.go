package rewrites

import (
	"errors"
	regexp "github.com/dlclark/regexp2"
	"strconv"
	"strings"

	C "github.com/Dreamacro/clash/constant"

	"github.com/gofrs/uuid"
)

var errInvalid = errors.New("invalid rewrite rule")

type RewriteRule struct {
	id          string
	urlRegx     *regexp.Regexp
	ruleType    C.RewriteType
	ruleRegx    *regexp.Regexp
	rulePayload string
}

func (r *RewriteRule) ID() string {
	return r.id
}

func (r *RewriteRule) URLRegx() *regexp.Regexp {
	return r.urlRegx
}

func (r *RewriteRule) RuleType() C.RewriteType {
	return r.ruleType
}

func (r *RewriteRule) RuleRegx() *regexp.Regexp {
	return r.ruleRegx
}

func (r *RewriteRule) RulePayload() string {
	return r.rulePayload
}

func (r *RewriteRule) ReplaceURLPayload(matchSub []string) string {
	url := r.rulePayload

	l := len(matchSub)
	if l < 2 {
		return url
	}

	for i := 1; i < l; i++ {
		url = strings.ReplaceAll(url, "$"+strconv.Itoa(i), matchSub[i])
	}
	return url
}

func (r *RewriteRule) ReplaceSubPayload(oldData string) string {
	payload := r.rulePayload
	if r.ruleRegx == nil {
		return oldData
	}

	sub, err := r.ruleRegx.FindStringMatch(oldData)
	if err != nil {
		return oldData
	}

	var groups []string
	for _, fg := range sub.Groups() {
		groups = append(groups, fg.String())
	}

	l := len(groups)

	for i := 1; i < l; i++ {
		payload = strings.ReplaceAll(payload, "$"+strconv.Itoa(i), groups[i])
	}

	return strings.ReplaceAll(oldData, groups[0], payload)
}

func NewRewriteRule(urlRegx *regexp.Regexp, ruleType C.RewriteType, ruleRegx *regexp.Regexp, rulePayload string) *RewriteRule {
	id, _ := uuid.NewV4()
	return &RewriteRule{
		id:          id.String(),
		urlRegx:     urlRegx,
		ruleType:    ruleType,
		ruleRegx:    ruleRegx,
		rulePayload: rulePayload,
	}
}

var _ C.Rewrite = (*RewriteRule)(nil)
