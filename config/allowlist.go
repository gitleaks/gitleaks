package config

import (
	"errors"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"golang.org/x/exp/maps"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

type AllowlistMatchCondition int

const (
	AllowlistMatchOr AllowlistMatchCondition = iota
	AllowlistMatchAnd
)

func (a AllowlistMatchCondition) String() string {
	return [...]string{
		"OR",
		"AND",
	}[a]
}

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// MatchCondition determines whether all criteria must match. Defaults to "OR".
	MatchCondition AllowlistMatchCondition

	// Commits is a slice of commit SHAs that are allowed to be ignored.
	Commits []string

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Can be `match` or `line`.
	//
	// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
	//
	// If `line` the _Regexes_ will be tested against the entire line.
	//
	// If RegexTarget is empty, it will be tested against the found secret.
	RegexTarget string

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string

	// validated is an internal flag to track whether `Validate()` has been called.
	validated bool

	// commitMap is a normalized version of Commits, used for efficiency purposes.
	// TODO: possible optimizations so that both short and long hashes work.
	commitMap    map[string]struct{}
	regexPat     *regexp.Regexp
	pathPat      *regexp.Regexp
	stopwordTrie *ahocorasick.Trie
}

func (a *Allowlist) Validate() error {
	if a.validated {
		return nil
	}

	// Disallow empty allowlists.
	if len(a.Commits) == 0 &&
		len(a.Paths) == 0 &&
		len(a.Regexes) == 0 &&
		len(a.StopWords) == 0 {
		return errors.New("must contain at least one check for: commits, paths, regexes, or stopwords")
	}

	// Deduplicate commits and stopwords.
	if len(a.Commits) > 0 {
		uniqueCommits := make(map[string]struct{})
		for _, commit := range a.Commits {
			// Commits are case-insensitive.
			uniqueCommits[strings.TrimSpace(strings.ToLower(commit))] = struct{}{}
		}
		a.Commits = maps.Keys(uniqueCommits)
		a.commitMap = uniqueCommits
	}
	if len(a.StopWords) > 0 {
		uniqueStopwords := make(map[string]struct{})
		for _, stopWord := range a.StopWords {
			uniqueStopwords[strings.ToLower(stopWord)] = struct{}{}
		}

		values := maps.Keys(uniqueStopwords)
		a.StopWords = values
		a.stopwordTrie = ahocorasick.NewTrieBuilder().AddStrings(values).Build()
	}

	// Combine patterns into a single expression.
	if len(a.Paths) > 0 {
		a.pathPat = joinRegexOr(a.Paths)
	}
	if len(a.Regexes) > 0 {
		a.regexPat = joinRegexOr(a.Regexes)
	}

	a.validated = true
	return nil
}

// CommitAllowed returns true if the commit is allowed to be ignored.
func (a *Allowlist) CommitAllowed(c string) (bool, string) {
	if a == nil || c == "" {
		return false, ""
	}
	if a.commitMap != nil {
		if _, ok := a.commitMap[strings.ToLower(c)]; ok {
			return true, ""
		}
	} else if len(a.Commits) > 0 {
		for _, commit := range a.Commits {
			if commit == c {
				return true, c
			}
		}
	}
	return false, ""
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	if a == nil || path == "" {
		return false
	}
	if a.pathPat != nil {
		return a.pathPat.MatchString(path)
	} else if len(a.Paths) > 0 {
		return anyRegexMatch(path, a.Paths)
	}
	return false
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(secret string) bool {
	if a == nil || secret == "" {
		return false
	}
	if a.regexPat != nil {
		return a.regexPat.MatchString(secret)
	} else if len(a.Regexes) > 0 {
		return anyRegexMatch(secret, a.Regexes)
	}
	return false
}

func (a *Allowlist) ContainsStopWord(s string) (bool, string) {
	if a == nil || s == "" {
		return false, ""
	}

	s = strings.ToLower(s)
	if a.stopwordTrie != nil {
		if m := a.stopwordTrie.MatchFirstString(s); m != nil {
			return true, m.MatchString()
		}
	} else if len(a.StopWords) > 0 {
		for _, stopWord := range a.StopWords {
			if strings.Contains(s, stopWord) {
				return true, stopWord
			}
		}
	}
	return false, ""
}
