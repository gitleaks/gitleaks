package config

import (
	"math"
	"path/filepath"
	"regexp"
)

// Offender is a struct that contains the information matched when searching
// content and information on why it matched (i.e. the EntropyLevel)
type Offender struct {
	Match        string
	EntropyLevel float64
}

// IsEmpty checks to see if nothing was found in the match
func (o *Offender) IsEmpty() bool {
	return o.Match == ""
}

// ToString the contents of the match
func (o *Offender) ToString() string {
	return o.Match
}

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
}

// Inspect checks the content of a line for a leak
func (r *Rule) Inspect(line string) *Offender {
	match := r.Regex.FindString(line)

	// EntropyLevel -1 means not checked
	if match == "" {
		return &Offender{
			Match:        "",
			EntropyLevel: -1,
		}
	}

	// check if offender is allowed
	// EntropyLevel -1 means not checked
	if r.RegexAllowed(line) {
		return &Offender{
			Match:        "",
			EntropyLevel: -1,
		}
	}

	// check entropy
	groups := r.Regex.FindStringSubmatch(match)
	entropyWithinRange, entropyLevel := r.CheckEntropy(groups)

	if len(r.Entropies) != 0 && !entropyWithinRange {
		return &Offender{
			Match:        "",
			EntropyLevel: entropyLevel,
		}
	}

	// 0 is a match for the full regex pattern
	if 0 < r.ReportGroup && r.ReportGroup < len(groups) {
		match = groups[r.ReportGroup]
	}

	return &Offender{
		Match:        match,
		EntropyLevel: entropyLevel,
	}
}

// RegexAllowed checks if the content is allowlisted
func (r *Rule) RegexAllowed(content string) bool {
	return anyRegexMatch(content, r.AllowList.Regexes)
}

// CommitAllowed checks if a commit is allowlisted
func (r *Rule) CommitAllowed(commit string) bool {
	return r.AllowList.CommitAllowed(commit)
}

// CheckEntropy checks if there is an entropy leak
func (r *Rule) CheckEntropy(groups []string) (bool, float64) {
	var highestFound float64 = 0

	for _, e := range r.Entropies {
		if len(groups) > e.Group {
			entropy := shannonEntropy(groups[e.Group])
			if entropy >= e.Min && entropy <= e.Max {
				return true, entropy
			} else if entropy > highestFound {
				highestFound = entropy
			}
		}
	}

	if len(r.Entropies) == 0 {
		// entropies not checked
		return false, -1
	}

	// entropies checked but not within the range
	return false, highestFound
}

// HasFileOrPathLeakOnly first checks if there are no entropy/regex rules, then checks if
// there are any file/path leaks
func (r *Rule) HasFileOrPathLeakOnly(filePath string) bool {
	if r.Regex.String() != "" {
		return false
	}
	if len(r.Entropies) != 0 {
		return false
	}
	if r.AllowList.FileAllowed(filepath.Base(filePath)) || r.AllowList.PathAllowed(filePath) {
		return false
	}
	return r.HasFileLeak(filepath.Base(filePath)) || r.HasFilePathLeak(filePath)
}

// HasFileLeak checks if there is a file leak
func (r *Rule) HasFileLeak(fileName string) bool {
	return regexMatched(fileName, r.File)
}

// HasFilePathLeak checks if there is a path leak
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
