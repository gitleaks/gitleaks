package config

import (
	"regexp"
	"strings"
)

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Commits is a slice of commit SHAs that are allowed to be ignored.
	Commits []string

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string
}

// CommitAllowed returns true if the commit is allowed to be ignored.
func (a *Allowlist) CommitAllowed(c string) bool {
	if c == "" {
		return false
	}
	for _, commit := range a.Commits {
		if commit == c {
			return true
		}
	}
	return false
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	return anyRegexMatch(path, a.Paths)
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(s string) bool {
	return anyRegexMatch(s, a.Regexes)
}

func (a *Allowlist) ContainsStopWord(s string) bool {
	s = strings.ToLower(s)
	for _, stopWord := range a.StopWords {
		if strings.Contains(s, strings.ToLower(stopWord)) {
			return true
		}
	}
	return false
}
