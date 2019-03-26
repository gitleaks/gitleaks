package main

import "math"

// getShannonEntropy https://en.wiktionary.org/wiki/Shannon_entropy
func getShannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

func entropyIsHighEnough(entropy float64) bool {
	if entropy >= opts.Entropy && len(config.Entropy.entropyRanges) == 0 {
		return true
	}

	for _, eR := range config.Entropy.entropyRanges {
		if entropy > eR.v1 && entropy < eR.v2 {
			return true
		}
	}

	return false
}

func highEntropyLineIsALeak(line string) bool {
	if !opts.NoiseReduction {
		return true
	}

	for _, re := range config.Entropy.regexes {
		if re.FindString(line) != "" {
			return true
		}
	}

	return false
}
