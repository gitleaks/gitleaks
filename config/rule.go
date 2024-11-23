package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule contain information that define details on how to detect secrets
type Rule struct {
	// RuleID is a unique identifier for this rule
	RuleID string `toml:"id"`

	// Description is the description of the rule.
	Description string `toml:"description"`

	// Regex is a golang regular expression used to detect secrets.
	Regex *regexp.Regexp `toml:"regex,omitempty"`

	// SecretGroup is an int used to extract secret from regex
	// match and used as the group that will have its entropy
	// checked if `entropy` is set.
	SecretGroup int `toml:"secretGroup,omitempty"`

	// Entropy is a float representing the minimum shannon
	// entropy a regex group must have to be considered a secret.
	Entropy float64 `toml:"entropy,omitempty"`

	// Path is a golang regular expression used to
	// filter secrets by path
	Path *regexp.Regexp `toml:"path,omitempty"`

	// Tags is an array of strings used for metadata
	// and reporting purposes.
	Tags []string `toml:"tags,omitempty"`

	// Keywords are used for pre-regex check filtering. Rules that contain
	// keywords will perform a quick string compare check to make sure the
	// keyword(s) are in the content being scanned.
	Keywords []string `toml:"keywords,omitempty"`

	// Allowlists allows a rule to be ignored for specific commits, paths, regexes, and/or stopwords.
	Allowlists []Allowlist `toml:"allowlists,omitempty"`
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

	// Ensure the rule actually matches something.
	if r.Regex == nil && r.Path == nil {
		return fmt.Errorf("%s: both |regex| and |path| are empty, this rule will have no effect", r.RuleID)
	}

	// Ensure |secretGroup| works.
	if r.Regex != nil && r.SecretGroup > r.Regex.NumSubexp() {
		return fmt.Errorf("%s: invalid regex secret group %d, max regex secret group %d", r.RuleID, r.SecretGroup, r.Regex.NumSubexp())
	}

	return nil
}
