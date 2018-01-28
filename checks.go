package main

import (
	"fmt"
	"github.com/nbutton23/zxcvbn-go"
	"strings"
)

// check each line of a diff and see if there are any potential
// secrets
func checkRegex(diff string) ([]string, bool) {
	var match string
	var results []string
	secretsPresent := false
	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		for _, re := range regexes {
			match = re.FindString(line)
			if len(match) == 0 {
				continue
			}
			secretsPresent = true
			results = append(results, line)
		}
	}
	return results, secretsPresent
}

// checkEntropy determines whether target contains enough
// entropy for a hash
func checkEntropy(target string) bool {
	index := assignRegex.FindStringIndex(target)
	if len(index) == 0 {
		return false
	}
	target = strings.Trim(target[index[1]:len(target)], " ")
	entropy := zxcvbn.PasswordStrength(target, nil).Entropy
	// tune this/make option
	if entropy > 70 {
		return true
	}
	return false
}
