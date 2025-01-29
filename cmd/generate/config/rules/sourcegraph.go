package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SourceGraph() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sourcegraph-access-token",
		Description: "Sourcegraph is a code search and navigation engine.",
		Regex:       utils.GenerateUniqueTokenRegex(`\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b`, true),
		Entropy:     3,
		Keywords:    []string{"sgp_", "sourcegraph"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sgp_", secrets.NewSecret(`\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b`))
	fps := []string{
		`sgp_5555555dAAAAA7777777CcccCFaaaaaaaaaaaaaa`,                    // low entropy
		`sgp_local_d45b6G86aBb0F2Cee943902dbaDBCFCFDD1dA089`,              // invalid case
		`sgp_652d9a2e48FC7E!FcDbEA1BC2E2A6CE23cFe7F7D`,                    // invalid character
		`sgp_78Ad84a5B6e8A2fE5B_4085FB0ccaDDd29DB66Fd7FE9bA2C1cdCE8400CD`, // invalid length
		`BcAeb6640ad7DAD46AD73687946Ce85047d5C9Bb`,
	}
	return utils.Validate(r, tps, fps)
}
