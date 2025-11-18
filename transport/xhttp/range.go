package xhttp

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/randv2"
)

// Range represents a [from, to] interval.
// When From == To the value is fixed.
type Range struct {
	From int32 `proxy:"from" json:"from"`
	To   int32 `proxy:"to" json:"to"`
}

// UnmarshalText implements encoding.TextUnmarshaler allowing values like "100-1000" or "128".
func (r *Range) UnmarshalText(text []byte) error {
	str := strings.TrimSpace(string(text))
	if str == "" {
		return nil
	}
	if strings.Contains(str, "-") {
		parts := strings.SplitN(str, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid range %q", str)
		}
		from, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid range %q: %w", str, err)
		}
		to, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid range %q: %w", str, err)
		}
		r.From = int32(from)
		r.To = int32(to)
		return nil
	}

	value, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid range %q: %w", str, err)
	}
	r.From = int32(value)
	r.To = int32(value)
	return nil
}

// UnmarshalJSON accepts number, string or object values.
func (r *Range) UnmarshalJSON(data []byte) error {
	switch {
	case len(data) == 0:
		return nil
	case data[0] == '"':
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		return r.UnmarshalText([]byte(text))
	case data[0] == '{':
		type alias Range
		var tmp alias
		if err := json.Unmarshal(data, &tmp); err != nil {
			return err
		}
		r.From = tmp.From
		r.To = tmp.To
		return nil
	default:
		var value int32
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		r.From = value
		r.To = value
		return nil
	}
}

// MarshalJSON implements json.Marshaler.
func (r Range) MarshalJSON() ([]byte, error) {
	if r.From == r.To {
		return json.Marshal(r.From)
	}
	type alias Range
	return json.Marshal(alias(r))
}

// IsZero reports whether the range is uninitialized.
func (r Range) IsZero() bool {
	return r.From == 0 && r.To == 0
}

// WithDefault returns range ensuring non-zero values.
func (r Range) WithDefault(from, to int32) Range {
	if r.IsZero() {
		return Range{From: from, To: to}
	}
	if r.To == 0 {
		r.To = r.From
	}
	if r.From == 0 {
		r.From = r.To
	}
	if r.To < r.From {
		r.From, r.To = r.To, r.From
	}
	return r
}

// Random selects a value within the range.
func (r Range) Random() int32 {
	if r.From == r.To {
		return r.From
	}
	if r.To < r.From {
		log.Warnln("xhttp: invalid range [%d, %d], swapping bounds", r.From, r.To)
		r.From, r.To = r.To, r.From
	}
	delta := r.To - r.From + 1
	if delta <= 1 {
		return r.From
	}
	return r.From + int32(randv2.IntN(int(delta)))
}
