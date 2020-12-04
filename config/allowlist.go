package config

import "regexp"

// AllowList is struct containing items that if encountered will allowlist
// a commit/line of code that would be considered a leak.
type AllowList struct {
	Description string
	Regexes     []*regexp.Regexp
	Commits     []string
	Files       []*regexp.Regexp
	Paths       []*regexp.Regexp
	Repos       []*regexp.Regexp
}

func (a *AllowList) CommitAllowed(commit string) bool {
	for _, hash := range a.Commits {
		if commit == hash {
			return true
		}
	}
	return false
}

func (a *AllowList) FileAllowed(fileName string) bool {
	return anyRegexMatch(fileName, a.Files)
}

func (a *AllowList) PathAllowed(filePath string) bool {
	return anyRegexMatch(filePath, a.Paths)
}

func (a *AllowList) RegexAllowed(content string) bool {
	return anyRegexMatch(content, a.Regexes)
}
