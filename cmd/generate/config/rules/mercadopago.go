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
		Description: "Detected a Mercado Pago access token, risking unauthorized payments, refunds and access to sales data.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:APP_USR|TEST)-[0-9]{10,20}-[0-9]{6}-[a-f0-9]{32}-[0-9]{6,12}`, false),
		Entropy:     3,
		Keywords: []string{
			"app_usr-",
			"test-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mercadopago", "APP_USR-"+secrets.NewSecret(utils.Numeric("16"))+"-"+secrets.NewSecret(utils.Numeric("6"))+"-"+secrets.NewSecret(utils.Hex("32"))+"-"+secrets.NewSecret(utils.Numeric("9")))
	tps = append(tps, utils.GenerateSampleSecrets("mercadopago", "TEST-"+secrets.NewSecret(utils.Numeric("16"))+"-"+secrets.NewSecret(utils.Numeric("6"))+"-"+secrets.NewSecret(utils.Hex("32"))+"-"+secrets.NewSecret(utils.Numeric("9")))...)
	tps = append(tps,
		`sdk = mercadopago.SDK("APP_USR-5021937746180352-101415-9f2c7e1a0b4d6e8f1a2b3c4d5e6f7a8b-602318874")`, // gitleaks:allow
		`MP_ACCESS_TOKEN=TEST-7310428865193047-052209-c4e1a97b2d3f08e65a1b9c7d4e2f6a83-918273645`,             // gitleaks:allow
	)
	fps := []string{
		// public keys are meant to be shipped to the browser
		`MP_PUBLIC_KEY=APP_USR-d0a26210-4f3b-4c8e-9a1d-479f0400869e`,
		`MP_PUBLIC_KEY=TEST-6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d`,
		// placeholders from the official docs
		`"access_token": "APP_USR-4934588586838432-XXXXXXXX-241983636"`,
		`MP_ACCESS_TOKEN=APP_USR-xxxxxxxxxxxxxxxx-xxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
