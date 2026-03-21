// Package wildcard modified IGLOU-EU/go-wildcard to support:
//
//	`*` matches zero or more characters
//	`?` matches exactly one character
//
// The original go-wildcard library used `.` to match exactly one character, and `?` to match zero or one character.
// `.` is a valid delimiter in domain name matching and should not be used as a wildcard.
// The `?` matching logic strictly matches only one character in most scenarios.
// So, the `?` matching logic in the original go-wildcard library has been removed and its wildcard `.` has been replaced with `?`.
package wildcard

// copy and modified from https://github.com/IGLOU-EU/go-wildcard/tree/ce22b7af48e487517a492d3727d9386492043e21
// which is licensed under OpenBSD's ISC-style license.
// Copyright (c) 2023 Iglou.eu contact@iglou.eu Copyright (c) 2023 Adrien Kara adrien@iglou.eu

func Match(pattern, s string) bool {
	if pattern == "" {
		return s == pattern
	}
	if pattern == "*" || s == pattern {
		return true
	}

	return matchByString(pattern, s)
}

func matchByString(pattern, s string) bool {
	var patternIndex, sIndex, lastStar int
	patternLen := len(pattern)
	sLen := len(s)
	star := -1

Loop:
	if sIndex >= sLen {
		goto checkPattern
	}

	if patternIndex >= patternLen {
		if star != -1 {
			patternIndex = star + 1
			lastStar++
			sIndex = lastStar
			goto Loop
		}
		return false
	}
	switch pattern[patternIndex] {
	case '?':
		// It matches any single character. So, we don't need to check anything.
	case '*':
		// '*' matches zero or more characters. Store its position and increment the pattern index.
		star = patternIndex
		lastStar = sIndex
		patternIndex++
		goto Loop
	default:
		// If the characters don't match, check if there was a previous '*' to backtrack.
		if pattern[patternIndex] != s[sIndex] {
			if star != -1 {
				patternIndex = star + 1
				lastStar++
				sIndex = lastStar
				goto Loop
			}

			return false
		}
	}

	patternIndex++
	sIndex++
	goto Loop

	// Check if the remaining pattern characters are '*', which can match the end of the string.
checkPattern:
	if patternIndex < patternLen {
		if pattern[patternIndex] == '*' {
			patternIndex++
			goto checkPattern
		}
	}

	return patternIndex == patternLen
}
