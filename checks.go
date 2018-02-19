package main

import (
	//"fmt"
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

func checkShannonEntropy(target string, entropyCutoff int) bool {
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

func checkStopWords(target string) bool {
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
			// fmt.Println("FOUND STOP", stopWord)
			return true
		}
	}
	return false

}
