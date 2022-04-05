package config

import (
	"regexp"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	// Description is the description of the rule.
	Description string

	// RuleID is a unique identifier for this rule
	RuleID string

	// Entropy is a float representing the minimum shannon
	// entropy a regex group must have to be considered a secret.
	Entropy float64

	// SecretGroup is an int used to extract secret from regex
	// match and used as the group that will have its entropy
	// checked if `entropy` is set.
	SecretGroup int

	// Regex is a golang regular expression used to detect secrets.
	Regex *regexp.Regexp

	// Path is a golang regular expression used to
	// filter secrets by path
	Path *regexp.Regexp

	// Tags is an array of strings used for metadata
	// and reporting purposes.
	Tags []string

	// Keywords are used for pre-regex check filtering. Rules that contain
	// keywords will perform a quick string compare check to make sure the
	// keyword(s) are in the content being scanned.
	Keywords []string

	// Allowlist allows a rule to be ignored for specific
	// regexes, paths, and/or commits
	Allowlist Allowlist
}
