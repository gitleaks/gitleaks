package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	// RuleID is a unique identifier for this rule
	RuleID string

	// Description is the description of the rule.
	Description string

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

// Validate guards against common misconfigurations.
func (r Rule) Validate() error {
	// Ensure |id| is present.
	if strings.TrimSpace(r.RuleID) == "" {
		// Try to provide helpful context, since |id| is empty.
		var context string
		if r.Regex != nil {
			context = ", regex: " + r.Regex.String()
		} else if r.Path != nil {
			context = ", path: " + r.Path.String()
		} else if r.Description != "" {
			context = ", description: " + r.Description
		}
		return fmt.Errorf("rule |id| is missing or empty" + context)
	}

	// TODO: uncomment this once it works with |extend|.
	// See: https://github.com/gitleaks/gitleaks/issues/1507#issuecomment-2352559213
	// Ensure the rule actually matches something.
	//if r.Regex == nil && r.Path == nil {
	//	return fmt.Errorf("%s: both |regex| and |path| are empty, this rule will have no effect", r.RuleID)
	//}

	// Ensure |secretGroup| works.
	if r.Regex != nil && r.SecretGroup > r.Regex.NumSubexp() {
		return fmt.Errorf("%s: invalid regex secret group %d, max regex secret group %d", r.RuleID, r.SecretGroup, r.Regex.NumSubexp())
	}

	return nil
}
