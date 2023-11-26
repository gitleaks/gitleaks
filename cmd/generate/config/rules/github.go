package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitHubPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
		RuleID:      "github-pat",
		Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Keywords:    []string{"ghp_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("github", "ghp_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}

func GitHubFineGrainedPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
		RuleID:      "github-fine-grained-pat",
		Regex:       regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`),
		Keywords:    []string{"github_pat_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("github", "github_pat_"+secrets.NewSecret(alphaNumeric("82"))),
	}
	return validate(r, tps, nil)
}

func GitHubOauth() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
		RuleID:      "github-oauth",
		Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Keywords:    []string{"gho_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("github", "gho_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}

func GitHubApp() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		RuleID:      "github-app-token",
		Regex:       regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
		Keywords:    []string{"ghu_", "ghs_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("github", "ghu_"+secrets.NewSecret(alphaNumeric("36"))),
		generateSampleSecret("github", "ghs_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}

func GitHubRefresh() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
		RuleID:      "github-refresh-token",
		Regex:       regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`),
		Keywords:    []string{"ghr_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("github", "ghr_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}
