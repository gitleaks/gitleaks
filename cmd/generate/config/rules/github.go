package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
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
	tps := []string{"gihubPAT := \"ghp_" + sampleAlphaNumeric36Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate github-pat")
		}
	}

	return &r
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
	tps := []string{"gihubAuth := \"gho_" + sampleAlphaNumeric36Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate github-oauth")
		}
	}

	return &r
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
	tps := []string{"gihubAuth := \"ghs_" + sampleAlphaNumeric36Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate github-app-token")
		}
	}

	return &r
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
	tps := []string{"gihubAuth := \"ghr_" + sampleAlphaNumeric36Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate github-refresh-token")
		}
	}

	return &r
}
