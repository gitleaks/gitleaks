package scan

import (
	"github.com/zricethezav/gitleaks/v7/config"
	"math"
	"regexp"
	"strings"

	""
)

func CommitAllowListed(r config.Rule, commit string) bool {
	return CommitAllowed(r.AllowList, commit)
}

func CheckLines(r config.Rule,content string) Leak {
	lineNumber := 1
	for _, line := range strings.Split(content, "\n") {
		offender := r.Regex.FindString(line)
		if offender == "" {
			continue
		}

		// check entropy
		groups := r.Regex.FindStringSubmatch(offender)
		if len(r.Entropies) != 0 && !ContainsEntropyLeak(r, groups) {
			continue
		}

		// 0 is a match for the full regex pattern
		if 0 < r.ReportGroup && r.ReportGroup < len(groups) {
			offender = groups[r.ReportGroup]
		}
		return Leak{
			LineNumber: lineNumber,
			Line:       line,
			Offender:   offender,
			Rule:       r.Description,
			Tags:       strings.Join(r.Tags, ", "),
		}
	}

	return Leak{}
}

func ContainsEntropyLeak(r config.Rule,groups []string) bool {
	// TODO come back to this... are we checking regular lines anymore?
	for _, e := range r.Entropies {
		if len(groups) > e.Group {
			entropy := shannonEntropy(groups[e.Group])
			if entropy >= e.Min && entropy <= e.Max {
				return true
			}
		}
	}
	return false

}

func HasFileLeak(r config.Rule,fileName string) bool {
	return regexMatched(fileName, r.File)
}

func HasFilePathLeak(r config.Rule,filePath string) bool {
	return regexMatched(filePath, r.Path)
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
func shannonEntropy(data string) (entropy float64) {
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

// regexMatched matched an interface to a regular expression. The interface f can
// be a string type or go-git *object.File type.
func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
}

// anyRegexMatch matched an interface to a regular expression. The interface f can
// be a string type or go-git *object.File type.
func anyRegexMatch(f string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if regexMatched(f, re) {
			return true
		}
	}
	return false
}
