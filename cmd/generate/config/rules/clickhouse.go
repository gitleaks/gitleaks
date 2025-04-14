package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func ClickHouseCloud() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "clickhouse-cloud-api-secret-key",
		Description: "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.",
		Regex:       regexp.MustCompile(`\b(4b1d[A-Za-z0-9]{38})\b`),
		Entropy:     3,
		Keywords: []string{
			"4b1d", // Prefix
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("ClickHouse", "4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z")
	tps = append(tps, utils.GenerateSampleSecrets("ClickHouse", "4b1d"+secrets.NewSecret("[A-Za-z0-9]{38}"))...)
	fps := []string{
		`key = 4b1dXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,    // Low entropy
		`key = adf4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z`, // Not start of a word
	}
	return utils.Validate(r, tps, fps)
}
