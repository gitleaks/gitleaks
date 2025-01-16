package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Meraki() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.",
		RuleID:      "meraki-api-key",
		Regex: utils.GenerateSemiGenericRegex([]string{"meraki"},
			`[0-9a-f]{40}`, false),
		Keywords: []string{"meraki", "cisco_meraki"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("meraki", secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		`│e9e0f062f587b_423bb6cc6328eb786d75b45783e.bfu`,
		`a1cdda32f587g423bb6cc6328Eb786d75b45783e`,
	}
	return utils.Validate(r, tps, fps)
}
