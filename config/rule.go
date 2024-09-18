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

	// Report indicates whether the rule should be scanned/reported.
	// This defaults to 'true' but can be set to 'false' for multi-part secret verification.
	Report bool
	Verify Verify
}

type Verify struct {
	HTTPVerb             string
	URL                  string
	Headers              map[string]string
	ExpectedStatus       []string
	ExpectedBodyContains []string

	// RequiredIDs is a set of other rule IDs that must be present for verification.
	requiredIDs      map[string]struct{}
	placeholderInUrl bool
	staticHeaders    map[string]string
	dynamicHeaders   map[string]string
	//buildRequestFunc *func(req *http.Request, rule Rule, finding report.Finding, findingsByRuleID map[string][]report.Finding) func() string
}

func (v Verify) GetRequiredIDs() map[string]struct{} {
	return v.requiredIDs
}

func (v Verify) GetPlaceholderInUrl() bool {
	return v.placeholderInUrl
}

func (v Verify) GetStaticHeaders() map[string]string {
	return v.staticHeaders
}

func (v Verify) GetDynamicHeaders() map[string]string {
	return v.dynamicHeaders
}
