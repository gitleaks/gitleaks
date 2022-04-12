package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
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
	tps := []string{"\"slackToken\": \"xoxb-" + sampleHex32Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate slack-access-token")
		}
	}

	return &r
}

func SlackWebHook() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Slack Webhook",
		RuleID:      "slack-web-hook",
		Regex: regexp.MustCompile(
			""),
		Keywords: []string{},
	}

	// validate
	tps := []string{""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate slack-web-hook")
		}
	}

	return &r
}
