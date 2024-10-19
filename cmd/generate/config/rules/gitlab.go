package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// overview with all GitLab tokens:
// https://docs.gitlab.com/ee/security/tokens/index.html#token-prefixes

func GitlabCiCdJobToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
		RuleID:      "gitlab-cicd-job-token",
		Regex:       regexp.MustCompile(`glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`),
		Keywords:    []string{"glcbt-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glcbt-"+secrets.NewSecret(utils.AlphaNumeric("5"))+"_"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabDeployToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
		RuleID:      "gitlab-deploy-token",
		Regex:       regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"gldt-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "gldt-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabFeatureFlagClientToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
		RuleID:      "gitlab-feature-flag-client-token",
		Regex:       regexp.MustCompile(`glffct-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glffct-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glffct-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabFeedToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab feed token, risking exposure of user data.",
		RuleID:      "gitlab-feed-token",
		Regex:       regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glft-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glft-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabIncomingMailToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
		RuleID:      "gitlab-incoming-mail-token",
		Regex:       regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`),
		Keywords:    []string{"glimt-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glimt-"+secrets.NewSecret(utils.AlphaNumeric("25"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabKubernetesAgentToken() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
		RuleID:      "gitlab-kubernetes-agent-token",
		Regex:       regexp.MustCompile(`glagent-[0-9a-zA-Z_\-]{50}`),
		Keywords:    []string{"glagent-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glagent-"+secrets.NewSecret(utils.AlphaNumeric("50"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabOauthAppSecret() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
		RuleID:      "gitlab-oauth-app-secret",
		Regex:       regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`),
		Keywords:    []string{"gloas-"},
		Entropy:     3,
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "gloas-"+secrets.NewSecret(utils.AlphaNumeric("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabPat() *config.Rule {
	r := config.Rule{
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		RuleID:      "gitlab-pat",
		Regex:       regexp.MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"glpat-"},
		Entropy:     3,
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabPipelineTriggerToken() *config.Rule {
	r := config.Rule{
		Description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		RuleID:      "gitlab-ptt",
		Regex:       regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		Keywords:    []string{"glptt-"},
		Entropy:     3,
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glptt-"+secrets.NewSecret(utils.Hex("40"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabRunnerRegistrationToken() *config.Rule {
	r := config.Rule{
		Description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		RuleID:      "gitlab-rrt",
		Regex:       regexp.MustCompile(`GR1348941[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"GR1348941"},
		Entropy:     3,
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "GR1348941"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabRunnerAuthenticationToken() *config.Rule {
	r := config.Rule{
		Description: "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		RuleID:      "gitlab-runner-authentication-token",
		Regex:       regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glrt-"},
		Entropy:     3,
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glrt-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabScimToken() *config.Rule {
	r := config.Rule{
		Description: "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
		RuleID:      "gitlab-scim-token",
		Regex:       regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20}`),
		Keywords:    []string{"glsoat-"},
		Entropy:     3,
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glsoat-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabSessionCookie() *config.Rule {
	r := config.Rule{
		Description: "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
		RuleID:      "gitlab-session-cookie",
		Regex:       regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`),
		Keywords:    []string{"_gitlab_session="},
		Entropy:     3,
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "_gitlab_session="+secrets.NewSecret(utils.AlphaNumeric("32"))),
	}
	return utils.Validate(r, tps, nil)
}
