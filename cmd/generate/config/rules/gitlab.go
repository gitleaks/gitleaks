package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitlabPat() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gitlab-pat",
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       regexp.MustCompile(`glpat-[\w-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glpat-"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	fps := []string{
		"glpat-XXXXXXXXXXX-XXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPipelineTriggerToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gitlab-ptt",
		Description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:       regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		Entropy:     3,
		Keywords:    []string{"glptt-"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glptt-"+secrets.NewSecret(utils.Hex("40"))),
	}
	fps := []string{
		"glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerRegistrationToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gitlab-rrt",
		Description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       regexp.MustCompile(`GR1348941[\w-]{20}`),
		Entropy:     3,
		Keywords:    []string{"GR1348941"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "GR1348941"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	fps := []string{
		"GR134894112312312312312312312",
		"GR1348941XXXXXXXXXXXXXXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}
