package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		RuleID:      "alibaba-access-key-id",
		Regex:       utils.GenerateUniqueTokenRegex(`LTAI[a-zA-Z0-9]{20}`, false),
		Keywords:    []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + secrets.NewSecret(utils.Hex("20")) + "\"",
	}
	fps := []string{
		"https://mp.weixin.qq.com/s?__biz=ltAiJTIfmTcHF0Z3fohrsVLP&wx_header=1&scene=27#wechat_redirect)",
	}
	return utils.Validate(r, tps, fps)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		RuleID:      "alibaba-secret-key",
		Regex: utils.GenerateSemiGenericRegex([]string{"alibaba"},
			utils.AlphaNumeric("30"), true),

		Keywords: []string{"alibaba"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("alibaba", secrets.NewSecret(utils.AlphaNumeric("30"))),
	}
	return utils.Validate(r, tps, nil)
}
