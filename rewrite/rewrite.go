package rewrites

import (
	regexp "github.com/dlclark/regexp2"
	"strconv"
	"strings"

	C "github.com/Dreamacro/clash/constant"

	"github.com/gofrs/uuid"
)

type RawMitmRule struct {
	Url    string        `yaml:"url" json:"url"`
	Action C.RewriteType `yaml:"action" json:"action"`
	Old    *string       `yaml:"old" json:"old"`
	New    string        `yaml:"new" json:"new"`
}

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

	for err == nil && sub != nil {
		var (
			groups   []string
			sPayload = payload
		)
		for _, fg := range sub.Groups() {
			groups = append(groups, fg.String())
		}

		l := len(groups)

		for i := 1; i < l; i++ {
			sPayload = strings.Replace(payload, "$"+strconv.Itoa(i), groups[i], 1)
		}

		oldData = strings.Replace(oldData, groups[0], sPayload, 1)

		sub, err = r.ruleRegx.FindNextMatch(sub)
	}

	return oldData
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
