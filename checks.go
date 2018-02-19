package main

import (
	"math"
	"strings"
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

// checkShannonEntropy checks entropy of target
func checkShannonEntropy(target string, entropyCutoff int) bool {
	index := assignRegex.FindStringIndex(target)
	if len(index) == 0 {
		return false
	}

	target = strings.Trim(target[index[1]:], " ")
	if len(target) > 100 {
		return false
	}

	var sum float64
	frq := make(map[rune]float64)

	for _, i := range target {
		frq[i]++
	}

	for _, v := range frq {
		f := v / float64(len(target))
		sum += f * math.Log2(f)
	}

	bits := int(math.Ceil(sum*-1)) * len(target)
	return bits > entropyCutoff
}

// containsStopWords checks if there are any stop words in target
func containsStopWords(target string) bool {
	stopWords := []string{
		"setting",
		"Setting",
		"SETTING",
		"info",
		"Info",
		"INFO",
		"env",
		"Env",
		"ENV",
		"environment",
		"Environment",
		"ENVIRONMENT",
	}

	for _, stopWord := range stopWords {
		if strings.Contains(target, stopWord) {
			return true
		}
	}
	return false
}
