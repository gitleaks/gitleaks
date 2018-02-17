package main

import (
	"strings"

	"github.com/nbutton23/zxcvbn-go"
)

// check each line of a diff and see if there are any potential secrets
// [1] https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf
func checkRegex(diff string) []string {
	var match string
	var results []string
	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		// doubtful a leak would be on a line > 120 characters
		if len(line) == 0 || len(line) > 120 {
			continue
		}
		for _, re := range regexes {
			match = re.FindString(line)
			if len(match) == 0 {
				continue
			}
			results = append(results, line)
		}
	}
	return results
}

// checkEntropy determines whether target contains enough
// entropy for a hash
// TODO remove stop words:
// setting(s), config(s), property(s), etc
func checkEntropy(target string) bool {
	index := assignRegex.FindStringIndex(target)
	if len(index) == 0 {
		return false
	}

	// TODO check for stop words here
	target = strings.Trim(target[index[1]:], " ")

	if len(target) > 70 {
		return false
	}

	entropy := zxcvbn.PasswordStrength(target, nil).Entropy

	// tune this/make option
	return entropy > 70
}
