package config

import (
	"math"
	"path/filepath"
	"regexp"
)

// Rule is a struct that contains information that is loaded from a gitleaks config.
// This struct is used in the Config struct as an array of Rules and is iterated
// over during an scan. Each rule will be checked. If a regex match is found AND
// that match is not allowlisted (globally or locally), then a leak will be appended
// to the final scan report.
type Rule struct {
	Description string
	Regex       *regexp.Regexp
	File        *regexp.Regexp
	Path        *regexp.Regexp
	ReportGroup int
	Tags        []string
	AllowList   AllowList
	Entropies   []Entropy
	RuleType
}

// RuleType
type RuleType int

const (
	TypeContent RuleType = iota + 1
	TypeFile
)

func (r *Rule) Inspect(line string) string {
	offender := r.Regex.FindString(line)
	if offender == "" {
		return ""
	}

	// check if offender is allowed
	if r.RegexAllowed(offender) {
		return ""
	}

	// check entropy
	groups := r.Regex.FindStringSubmatch(offender)
	if len(r.Entropies) != 0 && !r.ContainsEntropyLeak(groups) {
		return ""
	}

	// 0 is a match for the full regex pattern
	if 0 < r.ReportGroup && r.ReportGroup < len(groups) {
		offender = groups[r.ReportGroup]
	}
	return offender
}

func (r *Rule) RegexAllowed(content string) bool {
	return anyRegexMatch(content, r.AllowList.Regexes)
}

func (r *Rule) CommitAllowListed(commit string) bool {
	return r.AllowList.CommitAllowed(commit)
}

func (r *Rule) ContainsEntropyLeak(groups []string) bool {
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

func (r *Rule) HasFileOrPathLeakOnly(filePath string) bool {
	if r.Regex.String() != "" {
		return false
	}
	if len(r.Entropies) != 0 {
		return false
	}
	return r.HasFileLeak(filepath.Base(filePath)) || r.HasFilePathLeak(filePath)
}

func (r *Rule) HasFileLeak(fileName string) bool {
	return regexMatched(fileName, r.File)
}

func (r *Rule) HasFilePathLeak(filePath string) bool {
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
