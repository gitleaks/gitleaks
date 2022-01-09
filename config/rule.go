package config

import (
	"regexp"
	"strings"
)

type Rule struct {
	Description string
	RuleID      string
	Entropy     float64
	SecretGroup int
	Regex       *regexp.Regexp
	Path        *regexp.Regexp
	Tags        []string
	Allowlist   Allowlist
	Examples    []string
}

func (r *Rule) IncludeEntropy(secret string) (bool, float64) {
	// NOTE: this is a goofy hack to get around the fact there golang's regex engine
	// does not support positive lookaheads. Ideally we would want to add a
	// restriction on generic rules regex that requires the secret match group
	// contains both numbers and alphabetical characters. What this bit of code does is
	// check if the ruleid is prepended with "generic" and enforces the
	// secret contains both digits and alphabetical characters.
	if strings.HasPrefix(r.RuleID, "generic") {
		if !containsDigit(secret) {
			return false, 0.0
		}
	}
	// group = 0 will check the entropy of the whole regex match
	e := shannonEntropy(secret)
	if e > r.Entropy {
		return true, e
	}

	return false, e
}

func (r *Rule) EntropySet() bool {
	if r.Entropy == 0.0 {
		return false
	}
	return true
}
