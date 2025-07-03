package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func ArtifactoryApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-api-key",
		Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`AKCp[A-Za-z0-9]{69}`),
		Entropy:     3,
		Keywords:    []string{"AKCp"},
	}

	// validate
	tps := []string{
		"artifactoryApiKey := \"AKCp" + secrets.NewSecret(utils.Hex("69")) + "\"",
	}
	return utils.Validate(r, tps, nil)
}

func ArtifactoryReferenceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-reference-token",
		Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`cmVmd[A-Za-z0-9]{59}`),
		Entropy:     3,
		Keywords:    []string{"cmVmd"},
	}

	// validate
	tps := []string{
		"artifactoryRefToken := \"cmVmd" + secrets.NewSecret(utils.Hex("59")) + "\"",
	}
	return utils.Validate(r, tps, nil)
}
