package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func YandexAWSAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "yandex-aws-access-token",
		Description: "Yandex AWS Access Token",
		Regex: generateSemiGenericRegex([]string{"yandex"},
			`YC[a-zA-Z0-9_\-]{38}`),
		SecretGroup: 1,
		Keywords: []string{
			"yandex",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("yandex",
			secrets.NewSecret(`YC[a-zA-Z0-9_\-]{38}`)),
	}
	return validate(r, tps, nil)
}

func YandexAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "yandex-api-key",
		Description: "Yandex API Key",
		Regex: generateSemiGenericRegex([]string{"yandex"},
			`AQVN[A-Za-z0-9_\-]{35,38}`),
		SecretGroup: 1,
		Keywords: []string{
			"yandex",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("yandex",
			secrets.NewSecret(`AQVN[A-Za-z0-9_\-]{35,38}`)),
	}
	return validate(r, tps, nil)
}

func YandexAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "yandex-access-token",
		Description: "Yandex Access Token",
		Regex: generateSemiGenericRegex([]string{"yandex"},
			`t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`),
		SecretGroup: 1,
		Keywords: []string{
			"yandex",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("yandex",
			secrets.NewSecret(`t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`)),
	}
	return validate(r, tps, nil)
}
