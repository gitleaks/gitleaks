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
	if anyRegexMatch(path, a.Paths) {
		return true
	}
	return false
}

func (a *Allowlist) RegexAllowed(s string) bool {
	if anyRegexMatch(s, a.Regexes) {
		return true
	}

	return false
}
