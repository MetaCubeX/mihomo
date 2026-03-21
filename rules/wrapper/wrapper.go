package wrapper

import (
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type RuleWrapper struct {
	C.Rule
	disabled  atomic.Bool
	hitCount  atomic.Uint64
	hitAt     atomicTime
	missCount atomic.Uint64
	missAt    atomicTime
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

// atomicTime is a wrapper of [atomic.Int64] to provide atomic time storage.
// it only saves unix nanosecond export from time.Time.
// unlike atomic.TypedValue[time.Time] always escapes a new time.Time to heap when storing.
// that will lead to higher GC pressure during high frequency writes.
// be careful, it discards monotime so should not be used for internal time comparisons.
type atomicTime struct {
	i atomic.Int64
}

func (t *atomicTime) Load() time.Time {
	return time.Unix(0, t.i.Load())
}

func (t *atomicTime) Store(v time.Time) {
	t.i.Store(v.UnixNano())
}

func (t *atomicTime) Swap(v time.Time) time.Time {
	return time.Unix(0, t.i.Swap(v.UnixNano()))
}

func (t *atomicTime) CompareAndSwap(old, new time.Time) bool {
	return t.i.CompareAndSwap(old.UnixNano(), new.UnixNano())
}

func (t *atomicTime) MarshalText() ([]byte, error) {
	return t.Load().MarshalText()
}

func (t *atomicTime) UnmarshalText(text []byte) error {
	var v time.Time
	if err := v.UnmarshalText(text); err != nil {
		return err
	}
	t.Store(v)
	return nil
}
