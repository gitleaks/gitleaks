package config

import "regexp"

type Allowlist struct {
	Description string
	Regexes     []*regexp.Regexp
	Paths       []*regexp.Regexp
	Commits     []string
}

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

func (a *Allowlist) PathAllowed(path string) bool {
	return anyRegexMatch(path, a.Paths)
}

func (a *Allowlist) RegexAllowed(s string) bool {
	return anyRegexMatch(s, a.Regexes)
}
