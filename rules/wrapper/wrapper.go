package wrapper

import (
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
)

type RuleWrapper struct {
	C.Rule
	disabled  atomic.Bool
	hitCount  atomic.Uint64
	hitAt     atomic.TypedValue[time.Time]
	missCount atomic.Uint64
	missAt    atomic.TypedValue[time.Time]
}

func (r *RuleWrapper) IsDisabled() bool {
	return r.disabled.Load()
}

func (r *RuleWrapper) SetDisabled(v bool) {
	r.disabled.Store(v)
}

func (r *RuleWrapper) HitCount() uint64 {
	return r.hitCount.Load()
}

func (r *RuleWrapper) HitAt() time.Time {
	return r.hitAt.Load()
}

func (r *RuleWrapper) MissCount() uint64 {
	return r.missCount.Load()
}

func (r *RuleWrapper) MissAt() time.Time {
	return r.missAt.Load()
}

func (r *RuleWrapper) Unwrap() C.Rule {
	return r.Rule
}

func (r *RuleWrapper) Hit() {
	r.hitCount.Add(1)
	r.hitAt.Store(time.Now())
}

func (r *RuleWrapper) Miss() {
	r.missCount.Add(1)
	r.missAt.Store(time.Now())
}

func (r *RuleWrapper) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if r.IsDisabled() {
		return false, ""
	}
	ok, adapter := r.Rule.Match(metadata, helper)
	if ok {
		r.Hit()
	} else {
		r.Miss()
	}
	return ok, adapter
}

func NewRuleWrapper(rule C.Rule) C.RuleWrapper {
	return &RuleWrapper{Rule: rule}
}
