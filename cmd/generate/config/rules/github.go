package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var githubAllowlist = []*config.Allowlist{
	{
		Paths: []*regexp.Regexp{
			// https://github.com/octokit/auth-token.js/?tab=readme-ov-file#createtokenauthtoken-options
			regexp.MustCompile(`(?:^|/)@octokit/auth-token/README\.md$`),
		},
	},
}

func GitHubPat() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-pat",
		Description: "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
		Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghp_"},
		Allowlists:  githubAllowlist,
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("github", "ghp_"+secrets.NewSecret(utils.AlphaNumeric("36")))
	r.FPs = []string{
		"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return &r
}

func GitHubFineGrainedPat() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-fine-grained-pat",
		Description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
		Regex:       regexp.MustCompile(`github_pat_\w{82}`),
		Entropy:     3,
		Keywords:    []string{"github_pat_"},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("github", "github_pat_"+secrets.NewSecret(utils.AlphaNumeric("82")))
	r.FPs = []string{
		"github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return &r
}

func GitHubOauth() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-oauth",
		Description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
		Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"gho_"},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("github", "gho_"+secrets.NewSecret(utils.AlphaNumeric("36")))
	r.FPs = []string{
		"gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return &r
}

func GitHubApp() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-app-token",
		Description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		Regex:       regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghu_", "ghs_"},
		Allowlists:  githubAllowlist,
	}

	// validate
	tps := utils.GenerateSampleSecrets("github", "ghs_"+secrets.NewSecret(utils.AlphaNumeric("36")))
	r.TPs = append(tps, utils.GenerateSampleSecrets("github", "ghu_"+secrets.NewSecret(utils.AlphaNumeric("36")))...)
	r.FPs = []string{
		"ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return &r
}

func GitHubRefresh() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "github-refresh-token",
		Description: "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
		Regex:       regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`),
		Entropy:     3,
		Keywords:    []string{"ghr_"},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("github", "ghr_"+secrets.NewSecret(utils.AlphaNumeric("36")))
	r.FPs = []string{
		"ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	return &r
}
