package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord API key",
		RuleID:      "discord-api-token",
		Regex:       generateSemiGenericRegex([]string{"discord"}, hex64),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", sampleHex64Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate discord-api-token")
		}
	}
	return &r
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord client ID",
		RuleID:      "discord-client-id",
		Regex:       generateSemiGenericRegex([]string{"discord"}, numeric18),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", sampleNumeric18),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate discord-client-id")
		}
	}
	return &r
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord client secret",
		RuleID:      "discord-client-secret",
		Regex:       generateSemiGenericRegex([]string{"discord"}, extendedAlphaNumeric32),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", sampleExtendedAlphaNumeric32Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate discord-client-secret")
		}
	}
	return &r
}
