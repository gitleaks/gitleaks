package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitlabPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		RuleID:      "gitlab-pat",
		Regex:       regexp.MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"glpat-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("gitlab", "glpat-"+secrets.NewSecret(alphaNumeric("20"))),
	}
	return validate(r, tps, nil)
}

func GitlabPipelineTriggerToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		RuleID:      "gitlab-ptt",
		Regex:       regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		Keywords:    []string{"glptt-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("gitlab", "glptt-"+secrets.NewSecret(hex("40"))),
	}
	return validate(r, tps, nil)
}

func GitlabRunnerRegistrationToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		RuleID:      "gitlab-rrt",
		Regex:       regexp.MustCompile(`GR1348941[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"GR1348941"},
	}

	// validate
	tps := []string{
		generateSampleSecret("gitlab", "GR1348941"+secrets.NewSecret(alphaNumeric("20"))),
	}
	return validate(r, tps, nil)
}
