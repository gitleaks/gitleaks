package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// https://api.slack.com/authentication/token-types#bot
func SlackBotToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-bot-token",
		Description: "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.",
		Regex:       regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`),
		Entropy:     3,
		Keywords: []string{
			"xoxb",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bot", "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD")
	tps = append(tps,
		// https://github.com/metabase/metabase/blob/74cfb332140680425c7d37d347854160cc997ea8/frontend/src/metabase/admin/settings/slack/components/SlackForm/SlackForm.tsx#L47
		`"bot_token1": "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD"`, // gitleaks:allow
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#LL44C27-L44C86
		`"bot_token2": "xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4i57vs1MBS"`, // gitleaks:allow
		`"bot_token3": "xoxb-4614724432022-5152386766518-O5WzjWGLG0wcCm2WPrjEmnys"`,   // gitleaks:allow
		`"bot_token4": `+fmt.Sprintf(`"xoxb-%s-%s-%s"`, secrets.NewSecret(utils.Numeric("13")), secrets.NewSecret(utils.Numeric("12")), secrets.NewSecret(utils.AlphaNumeric("24"))),
	)
	fps := []string{
		"xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx",
		"xoxb-xxx",
		"xoxb-12345-abcd234",
		"xoxb-xoxb-my-bot-token",
	}
	return utils.Validate(r, tps, fps)
}

// https://api.slack.com/authentication/token-types#user
func SlackUserToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-user-token",
		Description: "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.",
		// The last segment seems to be consistently 32 characters. I've made it 28-34 just in case.
		Regex:    regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`),
		Entropy:  2,
		Keywords: []string{"xoxp-", "xoxe-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("user", "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef")
	tps = append(tps,
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L25
		`"user_token1": "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef"`, // gitleaks:allow
		// https://github.com/praetorian-inc/noseyparker/blob/16e0e5768fd14ea54f6c9a058566184d88343bb4/crates/noseyparker/data/default/rules/slack.yml#L29
		`"user_token2": "xoxp-283316862324-298911817009-298923149681-44f585044dace54f5701618e97cd1c0b"`, // gitleaks:allow
		// https://github.com/CloudBoost/cloudboost/blob/7ba2ed17099fa85e6fc652302822601283c6fa13/user-service/services/mailService.js#LL248C17-L248C92
		`"user_token3": "xoxp-11873098179-111402824422-234336993777-b96c9fb3b69f82ebb79d12f280779de1"`, // gitleaks:allow
		// https://github.com/evanyeung/terminal-slack/blob/b068f77808de72424d08b525d6cbf814849acd08/readme.md?plain=1#L66
		`"user_token4": "xoxp-254112160503-252950188691-252375361712-6cbf56aada30951a9d310a5f23d032a0"`,    // gitleaks:allow
		`"user_token5": "xoxp-4614724432022-4621207627011-5182682871568-1ddad9823e8528ad0f4944dfa3c6fc6c"`, // gitleaks:allow
		`"user_token6": `+fmt.Sprintf(`"xoxp-%s-%s-%s-%s"`, secrets.NewSecret(utils.Numeric("12")), secrets.NewSecret(utils.Numeric("13")), secrets.NewSecret(utils.Numeric("13")), secrets.NewSecret(utils.AlphaNumeric("32"))),
		// It's unclear what the `xoxe-` token means in this context, however, the format is similar to a user token.
		`"url_private": "https:\/\/files.slack.com\/files-pri\/T04MCQMEXQ9-F04MAA1PKE3\/image.png?t=xoxe-4726837507825-4848681849303-4856614048758-e0b1f3d4cb371f92260edb0d9444d206"`,
	)
	fps := []string{
		`https://docs.google.com/document/d/1W7KCxOxP-1Fy5EyF2lbJGE2WuKmu5v0suYqoHas1jRM`,
		`"token1": "xoxp-1234567890"`, // gitleaks:allow
		`"token2": "xoxp-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`, // gitleaks:allow
		`"token3": "xoxp-1234-1234-1234-4ddbc191d40ee098cbaae6f3523ada2d"`,                    // gitleaks:allow
		`"token4": "xoxp-572370529330-573807301142-572331691188-####################"`,        // gitleaks:allow
		// This technically matches the pattern but is an obvious false positive.
		// `"token5": "xoxp-000000000000-000000000000-000000000000-00000000000000000000000000000000"`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/token-types#app
func SlackAppLevelToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-app-token",
		Description: "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.",
		// This regex is based on a limited number of examples and may not be 100% accurate.
		Regex:    regexp.MustCompile(`(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`),
		Entropy:  2,
		Keywords: []string{"xapp"},
	}

	tps := utils.GenerateSampleSecrets("slack", "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e")
	tps = append(tps,
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L17
		`"token1": "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e"`, // gitleaks:allow
		`"token2": "xapp-1-IEMF8IMY1OQ-4037076220459-85c370b433e366de369c4ef5abdf41253519266982439a75af74a3d68d543fb6"`, // gitleaks:allow
		`"token3": "xapp-1-BM3V7LC51DA-1441525068281-86641a2582cd0903402ab523e5bcc53b8253098c31591e529b55b41974d2e82f"`, // gitleaks:allow
		`"token4": `+fmt.Sprintf(`"xapp-1-A%s-%s-%s"`, secrets.NewSecret(utils.Numeric("10")), secrets.NewSecret(utils.Numeric("13")), secrets.NewSecret(utils.AlphaNumeric("64"))),
	)
	return utils.Validate(r, tps, nil)
}

// Reference: https://api.slack.com/authentication/config-tokens
func SlackConfigurationToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-config-access-token",
		Description: "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.",
		Regex:       regexp.MustCompile(`(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`),
		Entropy:     2,
		Keywords:    []string{"xoxe.xoxb-", "xoxe.xoxp-"},
	}

	tps := utils.GenerateSampleSecrets("access", "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ")
	tps = append(tps,
		`"access_token1": "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ"`, // gitleaks:allow
		`"access_token2": "xoxe.xoxp-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ"`, // gitleaks:allow
		`"access_token3": "xoxe.xoxp-1-`+secrets.NewSecret(utils.AlphaNumeric("163"))+`"`,
		`"access_token4": "xoxe.xoxb-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ"`,
		`"access_token5": "xoxe.xoxb-1-`+secrets.NewSecret(utils.AlphaNumeric("165"))+`"`,
	)
	fps := []string{
		"xoxe.xoxp-1-SlackAppConfigurationAccessTokenHere",
		"xoxe.xoxp-1-RANDOMSTRINGHERE",
		"xoxe.xoxp-1-initial",
	}
	return utils.Validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/config-tokens
func SlackConfigurationRefreshToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-config-refresh-token",
		Description: "Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings.",
		Regex:       regexp.MustCompile(`(?i)xoxe-\d-[A-Z0-9]{146}`),
		Entropy:     2,
		Keywords:    []string{"xoxe-"},
	}

	tps := utils.GenerateSampleSecrets("refresh", "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg")
	tps = append(tps,
		`"refresh_token1": "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg"`, // gitleaks:allow
		`"refresh_token2": "xoxe-1-My0xLTM0MTQwNDE0MDE3Ni01MTgyMDc1NDk2MDgwLTU0MjQ1NjIwNzgxODEtNGJkYTZhYTUxY2M1ODk3ZTNkN2YzMTgxMDI1ZDQzNzgwNWY4NWQ0ODdhZGIzM2ViOGI0MTM0MjdlNGVmYzQ4Ng"`, // gitleaks:allow
		`"refresh_token3": "xoxe-1-`+secrets.NewSecret(utils.AlphaNumeric("146"))+`"`,
	)
	fps := []string{"xoxe-1-xxx", "XOxE-RROAmw, Home and Garden, 5:24, 20120323"}
	return utils.Validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/token-types#legacy_bot
func SlackLegacyBotToken() *config.Rule {
	r := config.Rule{
		RuleID:      "slack-legacy-bot-token",
		Description: "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.",
		// This rule is based off the limited information I could find and may not be 100% accurate.
		Regex:   regexp.MustCompile(`xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}`),
		Entropy: 2,
		Keywords: []string{
			"xoxb",
		},
	}

	tps := utils.GenerateSampleSecrets("slack", "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1")
	tps = append(tps,
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#LL42C38-L42C80
		`"bot_token1": "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1"`, // gitleaks:allow
		// https://heejune.me/2018/08/01/crashdump-analysis-automation-using-slackbot-python-cdb-from-windows/
		`"bot_token2": "xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP"`, // gitleaks:allow
		// https://github.com/praetorian-inc/noseyparker/blob/16e0e5768fd14ea54f6c9a058566184d88343bb4/crates/noseyparker/data/default/rules/slack.yml#L15
		`"bot_token3": "xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1"`, // gitleaks:allow
		// https://github.com/pulumi/examples/blob/32d9047c19c2a9380c04e57a764321c25eef45b0/aws-js-sqs-slack/README.md?plain=1#L39
		`"bot_token4": "xoxb-123456789012-Xw937qtWSXJss1lFaKe"`, // gitleaks:allow
		// https://github.com/ilyasProgrammer/Odoo-eBay-Amazon/blob/a9c4a8a7548b19027bc0fd904f8ae9249248a293/custom_logging/models.py#LL9C24-L9C66
		`"bot_token5": "xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS"`, // gitleaks:allow
		// https://github.com/jay-johnson/sci-pype/blob/6bff42ea4eb32d35b9f223db312e4cd0d3911100/src/pycore.py#L37
		`"bot_token6": "xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi"`, // gitleaks:allow
		// https://github.com/logicmoo/logicmoo_workspace/blob/2e1794f596121c9949deb3bfbd30d5b027a51d3d/packs_sys/slack_prolog/prolog/slack_client_old.pl#L28
		`"bot_token7": "xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK"`, // gitleaks:allow
		// https://github.com/sbarski/serverless-chatbot/blob/7d556897486f3fd53795907b7e33252e5cc6b3a3/Lesson%203/serverless.yml#L38
		`"bot_token8": "xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI"`,                                                                       // gitleaks:allow
		`"bot_token9": "xoxb-50014434-slacktokenx29U9X1bQ"`,                                                                               // gitleaks:allow
		`"bot_token10": `+fmt.Sprintf(`"xoxb-%s-%s`, secrets.NewSecret(utils.Numeric("10")), secrets.NewSecret(utils.AlphaNumeric("24"))), // gitleaks:allow
		`"bot_token11": `+fmt.Sprintf(`"xoxb-%s-%s`, secrets.NewSecret(utils.Numeric("12")), secrets.NewSecret(utils.AlphaNumeric("23"))), // gitleaks:allow
	)
	fps := []string{
		"xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
		"xoxb-Slack_BOT_TOKEN",
		"xoxb-abcdef-abcdef",
		// "xoxb-0000000000-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}

// Reference: https://api.slack.com/authentication/token-types#workspace
func SlackLegacyWorkspaceToken() *config.Rule {
	r := config.Rule{
		RuleID:      "slack-legacy-workspace-token",
		Description: "Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.",
		// This is by far the least confident pattern.
		Regex:   regexp.MustCompile(`xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}`),
		Entropy: 2,
		Keywords: []string{
			"xoxa",
			"xoxr",
		},
	}

	tps := utils.GenerateSampleSecrets("slack", "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c")
	tps = append(tps,
		`"access_token": "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c"`, // gitleaks:allow
		`"access_token1": `+fmt.Sprintf(`"xoxa-%s-%s`, secrets.NewSecret(utils.Numeric("1")), secrets.NewSecret(utils.AlphaNumeric("12"))),
		`"access_token2": `+fmt.Sprintf(`"xoxa-%s`, secrets.NewSecret(utils.AlphaNumeric("12"))),
		`"refresh_token1": `+fmt.Sprintf(`"xoxr-%s-%s`, secrets.NewSecret(utils.Numeric("1")), secrets.NewSecret(utils.AlphaNumeric("12"))),
		`"refresh_token2": `+fmt.Sprintf(`"xoxr-%s`, secrets.NewSecret(utils.AlphaNumeric("12"))),
	)
	fps := []string{
		// "xoxa-faketoken",
		// "xoxa-access-token-string",
		// "XOXa-nx991k",
		"https://github.com/xoxa-nyc/xoxa-nyc.github.io/blob/master/README.md",
	}
	return utils.Validate(r, tps, fps)
}

// References:
// - https://api.slack.com/authentication/token-types#legacy
// - https://api.slack.com/changelog/2016-05-19-authorship-changing-for-older-tokens
// - https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L29
// - https://gist.github.com/thesubtlety/a1c460d53df0837c5817c478b9f10588#file-local-slack-jack-py-L32
func SlackLegacyToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-legacy-token",
		Description: "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.",
		Regex:       regexp.MustCompile(`xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`),
		Entropy:     2,
		Keywords:    []string{"xoxo", "xoxs"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("slack", "xoxs-416843729158-132049654-5609968301-e708ba56e1")
	tps = append(tps,
		// https://github.com/GGStudy-DDUp/https-github.com-aldaor-HackerOneReports/blob/637e9261b63a7292a3a7ddf4bf13729c224d84df/PrivilegeEscalation/47940.txt#L23
		`"access_token1": "xoxs-3206092076-3204538285-3743137121-836b042620"`, // gitleaks:allow
		// https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L28
		`"access_token2": "xoxs-416843729158-132049654-5609968301-e708ba56e1"`, // gitleaks:allow
		// https://github.com/clr2of8/SlackExtract/blob/18d151152ff5a45b293d4b7193aa6d08f9ab1bfd/README.md?plain=1#L32
		`"access_token3": "xoxs-420083410720-421837374423-440811613314-977844f625b707d5b0b268206dbc92cbc85feef3e71b08e44815a8e6e7657190"`, // gitleaks:allow
		// https://github.com/zeroc00I/AllVideoPocsFromHackerOne/blob/95ae92f65ccef11c2c6acdaabfb7cc9b2b0eb4c6/jsonReports/61312.json#LL1C17-L1C17
		`"access_token4": "xoxs-4829527689-4829527691-4814341714-d0346ec616"`, // gitleaks:allow
		// https://github.com/ericvanderwal/general-playmaker/blob/34bd8e82e2d7b16ca9cc825d0c9d383b8378b550/Logic/setrandomseedtype.cs#LL783C15-L783C69
		`"access_token5": "xoxs-155191149137-155868813314-338998331396-9f6d235915"`, // gitleaks:allow
		`"access_token6": "xoxs-`+fmt.Sprintf("%s-%s-%s-%s", secrets.NewSecret(utils.Numeric("10")), secrets.NewSecret(utils.Numeric("10")), secrets.NewSecret(utils.Numeric("10")), secrets.NewSecret(utils.Hex("10")))+`"`,
		`"access_token7": "xoxo-523423-234243-234233-e039d02840a0b9379c"`, // gitleaks:allow
	)
	fps := []string{
		"https://indieweb.org/images/3/35/2018-250-xoxo-indieweb-1.jpg",
		"https://lh3.googleusercontent.com/-tWXjX3LUD6w/Ua4La_N5E2I/AAAAAAAAACg/qcm19xbEYa4/s640/EXO-XOXO-teaser-exo-k-34521098-720-516.jpg",
	}
	return utils.Validate(r, tps, fps)
}

func SlackWebHookUrl() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "slack-webhook-url",
		Description: "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.",
		// If this generates too many false-positives we should define an allowlist (e.g., "xxxx", "00000").
		Regex: regexp.MustCompile(
			`(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`),
		Keywords: []string{
			"hooks.slack.com",
		},
	}

	// validate
	tps := []string{
		"hooks.slack.com/services/" + secrets.NewSecret(utils.AlphaNumeric("44")),
		"http://hooks.slack.com/services/" + secrets.NewSecret(utils.AlphaNumeric("45")),
		"https://hooks.slack.com/services/" + secrets.NewSecret(utils.AlphaNumeric("46")),
		"http://hooks.slack.com/services/T024TTTTT/BBB72BBL/AZAAA9u0pA4ad666eMgbi555",   // gitleaks:allow
		"https://hooks.slack.com/services/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", // gitleaks:allow
		"hooks.slack.com/workflows/" + secrets.NewSecret(utils.AlphaNumeric("44")),
		"http://hooks.slack.com/workflows/" + secrets.NewSecret(utils.AlphaNumeric("45")),
		"https://hooks.slack.com/workflows/" + secrets.NewSecret(utils.AlphaNumeric("46")),
		"https://hooks.slack.com/workflows/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", // gitleaks:allow
		"http://hooks.slack.com/workflows/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",    // gitleaks:allow
		"https://hooks.slack.com/triggers/" + secrets.NewSecret(utils.AlphaNumeric("56")),
	}
	return utils.Validate(r, tps, nil)
}
