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
	var lastErotemeCluster byte
	var patternIndex, sIndex, lastStar, lastEroteme int
	patternLen := len(pattern)
	sLen := len(s)
	star := -1
	eroteme := -1

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
	// Removed dot matching as it conflicts with dot in domains.
	// case '.':
	// It matches any single character. So, we don't need to check anything.
	case '?':
		// '?' matches one character. Store its position and match exactly one character in the string.
		eroteme = patternIndex
		lastEroteme = sIndex
		lastErotemeCluster = byte(s[sIndex])
	case '*':
		// '*' matches zero or more characters. Store its position and increment the pattern index.
		star = patternIndex
		lastStar = sIndex
		patternIndex++
		goto Loop
	default:
		// If the characters don't match, check if there was a previous '?' or '*' to backtrack.
		if pattern[patternIndex] != s[sIndex] {
			if eroteme != -1 {
				patternIndex = eroteme + 1
				sIndex = lastEroteme
				eroteme = -1
				goto Loop
			}

			if star != -1 {
				patternIndex = star + 1
				lastStar++
				sIndex = lastStar
				goto Loop
			}

			return false
		}

		// If the characters match, check if it was not the same to validate the eroteme.
		if eroteme != -1 && lastErotemeCluster != byte(s[sIndex]) {
			eroteme = -1
		}
	}

	patternIndex++
	sIndex++
	goto Loop

	// Check if the remaining pattern characters are '*' or '?', which can match the end of the string.
checkPattern:
	if patternIndex < patternLen {
		if pattern[patternIndex] == '*' {
			patternIndex++
			goto checkPattern
		} else if pattern[patternIndex] == '?' {
			if sIndex >= sLen {
				sIndex--
			}
			patternIndex++
			goto checkPattern
		}
	}

	return patternIndex == patternLen
}
