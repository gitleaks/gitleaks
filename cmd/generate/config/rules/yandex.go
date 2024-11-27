package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func YandexAWSAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "yandex-aws-access-token",
		Description: "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.",
		Regex: utils.GenerateSemiGenericRegex([]string{"yandex"},
			`YC[a-zA-Z0-9_\-]{38}`, true),
		Keywords: []string{
			"yandex",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("yandex", secrets.NewSecret(`YC[a-zA-Z0-9_\-]{38}`))
	return utils.Validate(r, tps, nil)
}

func YandexAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "yandex-api-key",
		Description: "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.",
		Regex: utils.GenerateSemiGenericRegex([]string{"yandex"},
			`AQVN[A-Za-z0-9_\-]{35,38}`, true),

		Keywords: []string{
			"yandex",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("yandex", secrets.NewSecret(`AQVN[A-Za-z0-9_\-]{35,38}`))
	return utils.Validate(r, tps, nil)
}

func YandexAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "yandex-access-token",
		Description: "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.",
		Regex: utils.GenerateSemiGenericRegex([]string{"yandex"},
			`t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`, true),

		Keywords: []string{
			"yandex",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("yandex", secrets.NewSecret(`t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`))
	return utils.Validate(r, tps, nil)
}
