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
		Regex:       regexp.MustCompile(`\bAKCp[A-Za-z0-9]{69}\b`),
		Entropy:     4.5,
		Keywords:    []string{"AKCp"},
	}

	// validate
	tps := []string{
		"artifactoryApiKey := \"AKCp" + secrets.NewSecret(utils.AlphaNumeric("69")) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"AkCp" + secrets.NewSecret(utils.AlphaNumeric("69")) + "\"",
		"wrongLength := \"AkCp" + secrets.NewSecret(utils.AlphaNumeric("59")) + "\"",
		"partOfAlongUnrelatedBlob gYnkgAkCp" + secrets.NewSecret(utils.AlphaNumeric("69")) + "VyZSB2",
	}

	return utils.Validate(r, tps, fps)
}

func ArtifactoryReferenceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-reference-token",
		Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bcmVmd[A-Za-z0-9]{59}\b`),
		Entropy:     4.5,
		Keywords:    []string{"cmVmd"},
	}

	// validate
	tps := []string{
		"artifactoryRefToken := \"cmVmd" + secrets.NewSecret(utils.AlphaNumeric("59")) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := cmVmdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"cmVMd" + secrets.NewSecret(utils.AlphaNumeric("59")) + "\"",
		"wrongLength := \"cmVmd" + secrets.NewSecret(utils.AlphaNumeric("49")) + "\"",
		"partOfAlongUnrelatedBlob gYnkgcmVmd" + secrets.NewSecret(utils.AlphaNumeric("59")) + "VyZSB2",
	}

	return utils.Validate(r, tps, fps)
}
