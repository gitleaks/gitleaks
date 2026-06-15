package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MercadoPagoAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mercadopago-access-token",
		Description: "Detected a MercadoPago access token, risking unauthorized payment processing and exposure of financial account data.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:APP_USR|TEST)-[0-9]{10,16}-[0-9]{6}-[a-f0-9]{32}-[0-9]{6,12}`, false),
		Entropy:     2,
		Keywords: []string{
			"mercadopago",
			"mercadolibre",
			"APP_USR-",
			"TEST-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mercadopago", "APP_USR-"+secrets.NewSecret(utils.Numeric("12"))+"-"+secrets.NewSecret(utils.Numeric("6"))+"-"+secrets.NewSecret(utils.Hex("32"))+"-"+secrets.NewSecret(utils.Numeric("9")))
	tps = append(tps, utils.GenerateSampleSecrets("mercadopago", "TEST-"+secrets.NewSecret(utils.Numeric("12"))+"-"+secrets.NewSecret(utils.Numeric("6"))+"-"+secrets.NewSecret(utils.Hex("32"))+"-"+secrets.NewSecret(utils.Numeric("9")))...)
	fps := []string{"nonMatchingToken := \"APP_PUB-" + secrets.NewSecret(utils.Numeric("12")) + "\""}
	return utils.Validate(r, tps, fps)
}

func MercadoPagoPublicKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mercadopago-public-key",
		Description: "Detected a MercadoPago public key, potentially exposing payment integration details and client-side credentials.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:APP_USR|TEST)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, false),
		Entropy:     2,
		Keywords: []string{
			"mercadopago",
			"mercadolibre",
			"APP_USR-",
			"TEST-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mercadopago", "APP_USR-"+secrets.NewSecret(utils.Hex8_4_4_4_12()))
	tps = append(tps, utils.GenerateSampleSecrets("mercadopago", "TEST-"+secrets.NewSecret(utils.Hex8_4_4_4_12()))...)
	fps := []string{"nonMatchingToken := \"APP_PRV-" + secrets.NewSecret(utils.Hex8_4_4_4_12()) + "\""}
	return utils.Validate(r, tps, fps)
}
