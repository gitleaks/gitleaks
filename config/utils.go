package config

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

func anyRegexMatch(f string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if regexMatched(f, re) {
			return true
		}
	}
	return false
}

func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
}

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func EncodeBase62(num uint32, padLength int) string {
	if num == 0 {
		return strings.Repeat("0", padLength)
	}

	var result strings.Builder
	value := uint64(num) // Use uint64 for calculations to avoid overflow

	for value > 0 {
		result.WriteByte(base62Chars[value%62])
		value /= 62
	}

	// Reverse the string since we built it backwards
	encoded := result.String()
	runes := []rune(encoded)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	// Add leading zeros for padding
	finalResult := string(runes)
	if len(finalResult) < padLength {
		finalResult = strings.Repeat("0", padLength-len(finalResult)) + finalResult
	}

	return finalResult
}
