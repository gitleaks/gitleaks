package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func InfracostAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "infracost-api-token",
		Description: "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",
		Regex:       utils.GenerateUniqueTokenRegex(`ico-[a-zA-Z0-9]{32}`, false),
		Entropy:     3,
		Keywords:    []string{"ico-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("ico", "ico-"+secrets.NewSecret("[A-Za-z0-9]{32}"))
	tps = append(tps,
		`  variable {
    name = "INFRACOST_API_KEY"
    secret_value = "ico-mlCr1Mn3SRcRiZMObUZOTHLcgtH2Lpgt"
    is_secret = true
  }`,
		// TODO: New format with longer keys?
		//	`    headers = {
		//'X-Api-Key': 'ico-EeDdSfctrmjD14f45f45te5gJ7l6lw4o6M36sXT62a6',
		//'Content-Type': 'application/json',
		//}`,
	)
	fps := []string{
		// Low entropy
		`ico-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		// Invalid
		`http://assets.r7.com/assets/media_box_tv_tres_colunas/video_box.ico-7a388b69018576d24b59331fd60aab0c.png`,
		`https://explosivelab.notion.site/Pianificazione-Nerdz-Ng-pubblico-1bc826ecc0994dd8915be97fc3489cde?pvs=74`,
		`http://ece252-2.uwaterloo.ca:2540/image?q=gAAAAABdHkoqb9ZaJ3q4dlzEvTgG9WYwKcD9Aw7OUXeFicO-5M5IdNDjHBpKw7KBK3nCVqtuga4yzUaFEpJn8BqA1LzZprIJBw==`,
	}
	return utils.Validate(r, tps, fps)
}
