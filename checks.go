package main

import (
	_ "fmt"
	//"github.com/nbutton23/zxcvbn-go"
	"bytes"
	"math"
	"strings"
)

// check each line of a diff and see if there are any potential
// secrets
// https://people.eecs.berkeley.edu/~rohanpadhye/files/key_leaks-msr15.pdf
func checkRegex(diff string) []string {
	var match string
	var results []string
	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		// doubtful a leak would be on a line > 120 characters
		if len(line) == 0 || len(line) > 80 {
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

	target = strings.Trim(target[index[1]:len(target)], " ")
	entropy := shannonEntropy(target)

	// tune this/make option
	if entropy > 3.5 {
		return true
	}
	return false
}

func shannonEntropy(target string) float32 {
	freqs := make(map[byte]float64)
	targetBytes := []byte(target)
	entropy := float64(0)
	for i := 0; i < 256; i++ {
		freqs[byte(i)] = 0
	}
	ln := len(target)
	for k, _ := range freqs {
		px := float64(bytes.Count(targetBytes, []byte{k})) / float64(ln)
		freqs[k] = px
		if px > 0 {
			entropy += -float64(px) * math.Log2(px)
		}
	}
	return float32(entropy)
}
