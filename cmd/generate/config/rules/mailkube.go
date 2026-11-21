package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MailkubeAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailkube-api-key",
		Description: "Detected a mailkube API key, which can send email from the key's verified domain and read its organization and plan details.",
		// mk_<key id, 24>_<secret, 64>_<issuance tag: version character + 32 hex>
		Regex:    utils.GenerateUniqueTokenRegex(`mk_[a-z0-9]{24}_[A-Za-z0-9]{64}_[0-9a-z][0-9a-f]{32}`, false),
		Entropy:  3,
		Keywords: []string{"mk_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mailkube", "mk_"+
		secrets.NewSecret(utils.AlphaNumeric("24"))+"_"+
		secrets.NewSecret(`[A-Za-z0-9]{64}`)+"_"+
		secrets.NewSecret(`[0-9a-z][0-9a-f]{32}`))
	tps = append(tps,
		`MAILKUBE_API_KEY=mk_abcdefghijklmnopqrstuvwx_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d_1cbfd486fec407a9c8e6a37d8f22e0f12`,
		`Authorization: Bearer mk_abcdefghijklmnopqrstuvwx_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d_1cbfd486fec407a9c8e6a37d8f22e0f12`,
	)
	fps := []string{
		// the placeholder the documentation uses
		`MAILKUBE_API_KEY="mk_..."`,
		// a key issued before the issuance tag, which the gateway already refuses
		`MAILKUBE_API_KEY=mk_abcdefghijklmnopqrstuvwx_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d`,
		// an uppercase key id is not a key mailkube issues
		`MAILKUBE_API_KEY=mk_ABCDEFGHIJKLMNOPQRSTUVWX_aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3d_1cbfd486fec407a9c8e6a37d8f22e0f12`,
	}
	return utils.Validate(r, tps, fps)
}
