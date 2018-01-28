package main

import (
	_ "fmt"
	"strings"
)

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
