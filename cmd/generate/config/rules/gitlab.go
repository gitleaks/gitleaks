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
		Entropy:     3,
		Keywords:    []string{"glcbt-"},
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
		Entropy:     3,
		Keywords:    []string{"gldt-"},
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
		Entropy:     3,
		Keywords:    []string{"glffct-"},
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
		Entropy:     3,
		Keywords:    []string{"glft-"},
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
		Entropy:     3,
		Keywords:    []string{"glimt-"},
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
		Entropy:     3,
		Keywords:    []string{"glagent-"},
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
		Entropy:     3,
		Keywords:    []string{"gloas-"},
	}
	tps := []string{
		utils.GenerateSampleSecret("gitlab", "gloas-"+secrets.NewSecret(utils.AlphaNumeric("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func GitlabPat() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-pat",
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       regexp.MustCompile(`glpat-[\w-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glpat-"},
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	fps := []string{
		"glpat-XXXXXXXXXXX-XXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabPipelineTriggerToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-ptt",
		Description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:       regexp.MustCompile(`glptt-[0-9a-f]{40}`),
		Entropy:     3,
		Keywords:    []string{"glptt-"},
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "glptt-"+secrets.NewSecret(utils.Hex("40"))),
	}
	fps := []string{
		"glptt-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerRegistrationToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitlab-rrt",
		Description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       regexp.MustCompile(`GR1348941[\w-]{20}`),
		Entropy:     3,
		Keywords:    []string{"GR1348941"},
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "GR1348941"+secrets.NewSecret(utils.AlphaNumeric("20"))),
	}
	fps := []string{
		"GR134894112312312312312312312",
		"GR1348941XXXXXXXXXXXXXXXXXXXX",
	}
	return utils.Validate(r, tps, fps)
}

func GitlabRunnerAuthenticationToken() *config.Rule {
	r := config.Rule{
		Description: "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		RuleID:      "gitlab-runner-authentication-token",
		Regex:       regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`),
		Entropy:     3,
		Keywords:    []string{"glrt-"},
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
		Entropy:     3,
		Keywords:    []string{"glsoat-"},
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
		Entropy:     3,
		Keywords:    []string{"_gitlab_session="},
	}

	tps := []string{
		utils.GenerateSampleSecret("gitlab", "_gitlab_session="+secrets.NewSecret(utils.AlphaNumeric("32"))),
	}
	return utils.Validate(r, tps, nil)
}
