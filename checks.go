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
func checkShannonEntropy(target string, entropy64Cutoff int, entropyHexCutoff int) bool {
	var (
		sum             float64
		targetBase64Len int
		targetHexLen    int
		base64Freq      = make(map[rune]float64)
		hexFreq         = make(map[rune]float64)
		bits            int
	)

	// get assignment value
	index := assignRegex.FindStringIndex(target)
	if len(index) == 0 {
		return false
	}
	target = strings.Trim(target[index[1]:], " ")
	if len(target) > 100 {
		return false
	}

	// base64Shannon
	for _, i := range target {
		if strings.Contains(base64Chars, string(i)) {
			base64Freq[i]++
			targetBase64Len++
		}
	}
	for _, v := range base64Freq {
		f := v / float64(targetBase64Len)
		sum += f * math.Log2(f)
	}

	bits = int(math.Ceil(sum*-1)) * targetBase64Len
	if bits > entropy64Cutoff {
		return true
	}

	// hexShannon
	sum = 0
	for _, i := range target {
		if strings.Contains(hexChars, string(i)) {
			hexFreq[i]++
			targetHexLen++
		}
	}
	for _, v := range hexFreq {
		f := v / float64(targetHexLen)
		sum += f * math.Log2(f)
	}
	bits = int(math.Ceil(sum*-1)) * targetHexLen
	return bits > entropyHexCutoff
}

// containsStopWords checks if there are any stop words in target
func containsStopWords(target string) bool {
	for _, stopWord := range stopWords {
		if strings.Contains(target, stopWord) {
			return true
		}
	}
	return false
}
