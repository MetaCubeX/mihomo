package wildcard

/*
 * copy and modified from https://github.com/IGLOU-EU/go-wildcard/tree/ce22b7af48e487517a492d3727d9386492043e21
 *
 * Copyright (c) 2023 Iglou.eu <contact@iglou.eu>
 * Copyright (c) 2023 Adrien Kara <adrien@iglou.eu>
 *
 * Licensed under the BSD 3-Clause License,
 */

import (
	"testing"
)

// TestMatch validates the logic of wild card matching,
// it need to support '*', '?' and only validate for byte comparison
// over string, not rune or grapheme cluster
func TestMatch(t *testing.T) {
	cases := []struct {
		s       string
		pattern string
		result  bool
	}{
		{"", "", true},
		{"", "*", true},
		{"", "**", true},
		{"", "?", false},
		{"", "?*", false},
		{"", "*?", false},

		{"a", "", false},
		{"a", "a", true},
		{"a", "*", true},
		{"a", "**", true},
		{"a", "?", true},
		{"a", "?*", true},
		{"a", "*?", true},

		{"match the exact string", "match the exact string", true},
		{"do not match a different string", "this is a different string", false},
		{"Match The Exact String WITH DIFFERENT CASE", "Match The Exact String WITH DIFFERENT CASE", true},
		{"do not match a different string WITH DIFFERENT CASE", "this is a different string WITH DIFFERENT CASE", false},
		{"Do Not Match The Exact String With Different Case", "do not match the exact string with different case", false},
		{"match an emoji 😃", "match an emoji 😃", true},
		{"do not match because of different emoji 😃", "do not match because of different emoji 😄", false},
		{"🌅☕️📰👨‍💼👩‍💼🏢🖥️💼💻📊📈📉👨‍👩‍👧‍👦🍝🕰️💪🏋️‍♂️🏋️‍♀️🏋️‍♂️💼🚴‍♂️🚴‍♀️🚴‍♂️🛀💤🌃", "🌅☕️📰👨‍💼👩‍💼🏢🖥️💼💻📊📈📉👨‍👩‍👧‍👦🍝🕰️💪🏋️‍♂️🏋️‍♀️🏋️‍♂️💼🚴‍♂️🚴‍♀️🚴‍♂️🛀💤🌃", true},
		{"🌅☕️📰👨‍💼👩‍💼🏢🖥️💼💻📊📈📉👨‍👩‍👧‍👦🍝🕰️💪🏋️‍♂️🏋️‍♀️🏋️‍♂️💼🚴‍♂️🚴‍♀️🚴‍♂️🛀💤🌃", "🦌🐇🦡🐿️🌲🌳🏰🌳🌲🌞🌧️❄️🌬️⛈️🔥🎄🎅🎁🎉🎊🥳👨‍👩‍👧‍👦💏👪💖👩‍💼🛀", false},

		{"match a string with a *", "match a string *", true},
		{"match a string with a * at the beginning", "* at the beginning", true},
		{"match a string with two *", "match * with *", true},
		{"do not match a string with extra and a *", "do not match a string * with more", false},

		{"match a string with a ?", "match ? string with a ?", true},
		{"match a string with a ? at the beginning", "?atch a string with a ? at the beginning", true},
		{"match a string with two ?", "match a ??ring with two ?", true},
		{"do not match a string with extra ?", "do not match a string with extra ??", false},

		{"abc.edf.hjg", "abc.edf.hjg", true},
		{"abc.edf.hjg", "ab.cedf.hjg", false},
		{"abc.edf.hjg", "abc.edfh.jg", false},
		{"abc.edf.hjg", "abc.edf.hjq", false},

		{"abc.edf.hjg", "abc.*.hjg", true},
		{"abc.edf.hjg", "abc.*.hjq", false},
		{"abc.edf.hjg", "abc*hjg", true},
		{"abc.edf.hjg", "abc*hjq", false},
		{"abc.edf.hjg", "a*g", true},
		{"abc.edf.hjg", "a*q", false},

		{"abc.edf.hjg", "ab?.edf.hjg", true},
		{"abc.edf.hjg", "?b?.edf.hjg", true},
		{"abc.edf.hjg", "??c.edf.hjg", true},
		{"abc.edf.hjg", "a??.edf.hjg", true},
		{"abc.edf.hjg", "ab??.edf.hjg", false},
		{"abc.edf.hjg", "??.edf.hjg", false},
	}

	for i, c := range cases {
		t.Run(c.s, func(t *testing.T) {
			result := Match(c.pattern, c.s)
			if c.result != result {
				t.Errorf("Test %d: Expected `%v`, found `%v`; With Pattern: `%s` and String: `%s`", i+1, c.result, result, c.pattern, c.s)
			}
		})
	}
}

func match(pattern, name string) bool { // https://research.swtch.com/glob
	px := 0
	nx := 0
	nextPx := 0
	nextNx := 0
	for px < len(pattern) || nx < len(name) {
		if px < len(pattern) {
			c := pattern[px]
			switch c {
			default: // ordinary character
				if nx < len(name) && name[nx] == c {
					px++
					nx++
					continue
				}
			case '?': // single-character wildcard
				if nx < len(name) {
					px++
					nx++
					continue
				}
			case '*': // zero-or-more-character wildcard
				// Try to match at nx.
				// If that doesn't work out,
				// restart at nx+1 next.
				nextPx = px
				nextNx = nx + 1
				px++
				continue
			}
		}
		// Mismatch. Maybe restart.
		if 0 < nextNx && nextNx <= len(name) {
			px = nextPx
			nx = nextNx
			continue
		}
		return false
	}
	// Matched all of pattern to all of name. Success.
	return true
}

func FuzzMatch(f *testing.F) {
	f.Fuzz(func(t *testing.T, pattern, name string) {
		result1 := Match(pattern, name)
		result2 := match(pattern, name)
		if result1 != result2 {
			t.Fatalf("Match failed for pattern `%s` and name `%s`", pattern, name)
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	cases := []struct {
		s       string
		pattern string
		result  bool
	}{
		{"abc.edf.hjg", "abc.edf.hjg", true},
		{"abc.edf.hjg", "ab.cedf.hjg", false},
		{"abc.edf.hjg", "abc.edfh.jg", false},
		{"abc.edf.hjg", "abc.edf.hjq", false},

		{"abc.edf.hjg", "abc.*.hjg", true},
		{"abc.edf.hjg", "abc.*.hjq", false},
		{"abc.edf.hjg", "abc*hjg", true},
		{"abc.edf.hjg", "abc*hjq", false},
		{"abc.edf.hjg", "a*g", true},
		{"abc.edf.hjg", "a*q", false},

		{"abc.edf.hjg", "ab?.edf.hjg", true},
		{"abc.edf.hjg", "?b?.edf.hjg", true},
		{"abc.edf.hjg", "??c.edf.hjg", true},
		{"abc.edf.hjg", "a??.edf.hjg", true},
		{"abc.edf.hjg", "ab??.edf.hjg", false},
		{"abc.edf.hjg", "??.edf.hjg", false},

		{"r4.cdn-aa-wow-this-is-long-a1.video-yajusenpai1145141919810-oh-hell-yeah-this-is-also-very-long-and-sukka-the-fox-has-a-very-big-fluffy-fox-tail-ao-wu-ao-wu-regex-and-wildcard-both-might-have-deadly-back-tracing-issue-be-careful-or-use-linear-matching.com", "*.cdn-*-*.video**.com", true},
	}

	b.Run("Match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				result := Match(c.pattern, c.s)
				if c.result != result {
					b.Errorf("Test %d: Expected `%v`, found `%v`; With Pattern: `%s` and String: `%s`", i+1, c.result, result, c.pattern, c.s)
				}
			}
		}
	})

	b.Run("match", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				result := match(c.pattern, c.s)
				if c.result != result {
					b.Errorf("Test %d: Expected `%v`, found `%v`; With Pattern: `%s` and String: `%s`", i+1, c.result, result, c.pattern, c.s)
				}
			}
		}
	})
}
