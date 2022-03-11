package config

import (
	"regexp"
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
}

func (r *Rule) EntropySet() bool {
	if r.Entropy == 0.0 {
		return false
	}
	return true
}
