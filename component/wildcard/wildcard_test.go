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
		{"", "?", true},
		{"", "??", true},
		{"", "?*", true},
		{"", "*?", true},
		{"", ".", false},
		{"", ".?", false},
		{"", "?.", false},
		{"", ".*", false},
		{"", "*.", false},
		{"", "*.?", false},
		{"", "?.*", false},

		{"a", "", false},
		{"a", "a", true},
		{"a", "*", true},
		{"a", "**", true},
		{"a", "?", true},
		{"a", "??", true},
		{"a", ".", false},
		{"a", ".?", false},
		{"a", "?.", false},
		{"a", ".*", false},
		{"a", "*.", false},
		{"a", "*.?", false},
		{"a", "?.*", false},

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
		{"match a string with two ?", "match a string with two ??", true},
		{"match a optional char with a ?", "match a optional? char with a ?", true},
		{"match a optional   char with a ?", "match a optional?   char with a ?", true},
		{"do not match a string with extra and a ?", "do not match ? string with extra and a ? like this", false},

		{"do not match a string with a .", "do not match . string with a .", false},
		{"do not match a string with a . at the beginning", "do not .atch a string with a . at the beginning", false},
		{"do not match a string with two .", "do not match a ..ring with two .", false},
		{"do not match a string with extra .", "do not match a string with extra ..", false},

		{"A big brown fox jumps over the lazy dog, with all there wildcards friends", ". big?brown fox jumps over * wildcard. friend??", false},
		{"A big brown fox fails to jump over the lazy dog, with all there wildcards friends", ". big?brown fox jumps over * wildcard. friend??", false},

		{"domain a.b.c", "domain a.b.c", true},
		{"domain adb.c", "domain a.b.c", false},
		{"aaaa", "a*a", true},
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

func FuzzMatch(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		if !Match(string(s), string(s)) {
			t.Fatalf("%s does not match %s", s, s)
		}
	})
}
