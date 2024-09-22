package config

import (
	"fmt"
	"golang.org/x/exp/maps"
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
	Verify *Verify
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

type Verify struct {
	HTTPVerb             string
	URL                  string
	Headers              map[string]string
	ExpectedStatus       []int
	ExpectedBodyContains []string

	// RequiredIDs is a set of other rule IDs that must be present for verification.
	initialized      bool
	requiredIDs      map[string]struct{}
	placeholderInUrl bool
	staticHeaders    map[string]string
	dynamicHeaders   map[string]string
	//buildRequestFunc *func(req *http.Request, rule Rule, finding report.Finding, findingsByRuleID map[string][]report.Finding) func() string
}

func (v *Verify) GetRequiredIDs() map[string]struct{} {
	return v.requiredIDs
}

func (v *Verify) GetPlaceholderInUrl() bool {
	return v.placeholderInUrl
}

func (v *Verify) GetStaticHeaders() map[string]string {
	return v.staticHeaders
}

func (v *Verify) GetDynamicHeaders() map[string]string {
	return v.dynamicHeaders
}

var (
	verifyPlaceholderPat = regexp.MustCompile(`(?i)\${([a-z0-9\-]+)}`)
)

func (v *Verify) Validate(ruleID string) error {
	if v.initialized {
		return nil
	}

	// TODO: Check that there's some sort of substitution happening here.
	v.requiredIDs = map[string]struct{}{}
	// Parse URL.
	for _, match := range verifyPlaceholderPat.FindAllStringSubmatch(v.URL, -1) {
		if !v.placeholderInUrl {
			v.placeholderInUrl = true
		}
		v.requiredIDs[match[1]] = struct{}{}
	}
	if err := checkVerifyHelperFuncs(v.URL); err != nil {
		return fmt.Errorf("%s: %w", ruleID, err)
	}

	// Parse headers.
	v.staticHeaders = map[string]string{}
	v.dynamicHeaders = map[string]string{}
	for k, val := range v.Headers {
		matches := verifyPlaceholderPat.FindAllStringSubmatch(val, -1)
		if len(matches) == 0 {
			v.staticHeaders[k] = val
			continue
		}

		v.dynamicHeaders[k] = val
		for _, match := range matches {
			v.requiredIDs[match[1]] = struct{}{}
		}

		if err := checkVerifyHelperFuncs(val); err != nil {
			return fmt.Errorf("%s: %w", ruleID, err)
		}
	}

	// Parse expected statuses.
	for _, s := range v.ExpectedStatus {
		if s < 100 || s > 599 {
			return fmt.Errorf("%s: invalid status value: %d", ruleID, s)
		}
	}

	// TODO: Check in body as well
	// TODO: Handle things like base64-encoding
	if len(v.requiredIDs) == 0 {
		return fmt.Errorf("%s: verify config does not contain any placeholders (${rule-id})", ruleID)
	} else if _, ok := v.requiredIDs[ruleID]; !ok {
		return fmt.Errorf("%s: verify config does not contain a placeholder for the rule's output (${%s})", ruleID, ruleID)
	} else {
		delete(v.requiredIDs, ruleID)
	}

	v.initialized = true
	if len(v.requiredIDs) == 0 {
		v.requiredIDs = nil
	}
	if len(v.staticHeaders) == 0 {
		v.staticHeaders = nil
	}
	if len(v.dynamicHeaders) == 0 {
		v.dynamicHeaders = nil
	}

	return nil
}

var (
	verifyHelperFuncPat = regexp.MustCompile(`\${([A-Za-z0-9]{3,15})\("(.+?)"\)}`)
	helperFuncs         = map[string]struct{}{
		"base64":    {},
		"urlEncode": {},
	}
)

func checkVerifyHelperFuncs(s string) error {
	for _, match := range verifyHelperFuncPat.FindAllStringSubmatch(s, -1) {
		if _, ok := helperFuncs[match[1]]; !ok {
			return fmt.Errorf("unknown helper function '%s' (known: %v)", match[1], maps.Keys(helperFuncs))
		}
	}
	return nil
}
