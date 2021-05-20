package config

import (
	"regexp"
)

// used for ignoring .git directories when the --no-git flag is set
// related issue: https://github.com/zricethezav/gitleaks/issues/486
const dotGit = `/\.git/`

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

// CommitAllowed checks if a commit is allowlisted
func (a *AllowList) CommitAllowed(commit string) bool {
	for _, hash := range a.Commits {
		if commit == hash {
			return true
		}
	}
	return false
}

// FileAllowed checks if a file is allowlisted
func (a *AllowList) FileAllowed(fileName string) bool {
	return anyRegexMatch(fileName, a.Files)
}

// PathAllowed checks if a path is allowlisted
func (a *AllowList) PathAllowed(filePath string) bool {
	return anyRegexMatch(filePath, a.Paths)
}

// RegexAllowed checks if a regex is allowlisted
func (a *AllowList) RegexAllowed(content string) bool {
	return anyRegexMatch(content, a.Regexes)
}

// RepoAllowed checks if a regex is allowlisted
func (a *AllowList) RepoAllowed(repo string) bool {
	return anyRegexMatch(repo, a.Repos)
}

// IgnoreDotGit appends a `\.git` rule to ignore all .git paths. This is used for --no-git scans
func (a *AllowList) IgnoreDotGit() error {
	re, err := regexp.Compile(dotGit)
	if err != nil {
		return err
	}
	a.Paths = append(a.Paths, re)
	return nil
}
