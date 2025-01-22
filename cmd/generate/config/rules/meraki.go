package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Meraki() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cisco-meraki-api-key",
		Description: "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`(?-i:[Mm]eraki|MERAKI)`}, `[0-9a-f]{40}`, false),
		Entropy:     3,
		Keywords:    []string{"meraki"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("meraki", secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		`meraki: aaaaaaaaaa1111111111bbbbbbbbbb2222222222`,                                   // low entropy
		`meraki-api-key: acdeFf05b1a6d4c890237bf08c5e6e8d2b4d0f2e`,                           // invalid case
		`meraki: abdefghjk0123456789mnopqrstuvwx12345678`,                                    // invalid character
		`meraki_token = 5cb4a5f04cd412fe946667b17f0129ba17aeb2e0c7b5b7264efcebf7d022bfe2R21`, // invalid length
		`ReactNativeCameraKit: f15a5a04b0f6dc6073e6db0296e6ef2d8b8d2522`,
	}
	return utils.Validate(r, tps, fps)
}
