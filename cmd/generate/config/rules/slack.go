package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func SlackAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack token",
		RuleID:      "slack-access-token",
		Regex: regexp.MustCompile(
			"xox[baprs]-([0-9a-zA-Z]{10,48})"),
		Keywords: []string{
			"xoxb",
			"xoxa",
			"xoxp",
			"xoxr",
			"xoxs",
		},
	}

	// validate
	tps := []string{
		"\"slackToken\": \"xoxb-" + sampleHex32Token + "\"",
	}
	return validate(r, tps)
}

func SlackWebHook() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Webhook",
		RuleID:      "slack-web-hook",
		Regex: regexp.MustCompile(
			`https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,46}`),
		Keywords: []string{
			"hooks.slack.com",
		},
	}

	// validate
	tps := []string{
		"https://hooks.slack.com/services/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // gitleaks:allow
	}
	return validate(r, tps)
}
