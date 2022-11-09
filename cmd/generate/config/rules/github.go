package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitHubPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "GitHub Personal Access Token",
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
		Description: "GitHub Fine-Grained Personal Access Token",
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
		Description: "GitHub OAuth Access Token",
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
		Description: "GitHub App Token",
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
		Description: "GitHub Refresh Token",
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
