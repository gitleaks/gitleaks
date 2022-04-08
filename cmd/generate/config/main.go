package main

import (
	"os"
	"text/template"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	templatePath = "rules/rule.tmpl"
)

// TODO introduce skiplists:
// https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-skipfish.fuzz.txt

func main() {
	configRules := []*config.Rule{}
	configRules = append(configRules, rules.AgeSecretKey())
	configRules = append(configRules, rules.AdobeClientID())
	configRules = append(configRules, rules.AdobeClientSecret())
	configRules = append(configRules, rules.AlibabaAccessKey())
	configRules = append(configRules, rules.AlibabaSecretKey())
	configRules = append(configRules, rules.AsanaClientID())
	configRules = append(configRules, rules.AsanaClientSecret())
	configRules = append(configRules, rules.Atlassian())
	configRules = append(configRules, rules.BitBucketClientID())
	configRules = append(configRules, rules.BitBucketClientSecret())
	configRules = append(configRules, rules.Beamer())
	configRules = append(configRules, rules.Clojars())
	configRules = append(configRules, rules.Contentful())
	configRules = append(configRules, rules.Databricks())
	configRules = append(configRules, rules.DiscordAPIToken())
	configRules = append(configRules, rules.DiscordClientID())
	configRules = append(configRules, rules.DiscordClientSecret())
	configRules = append(configRules, rules.AWS())
	configRules = append(configRules, rules.Facebook())
	// TODO fix gcp
	// configRules = append(configRules, rules.GCPServiceAccount())
	configRules = append(configRules, rules.GitHubPat())
	configRules = append(configRules, rules.GitHubOauth())
	configRules = append(configRules, rules.GitHubApp())
	configRules = append(configRules, rules.GitHubRefresh())
	configRules = append(configRules, rules.Gitlab())
	configRules = append(configRules, rules.Heroku())
	configRules = append(configRules, rules.OpenSSH())
	configRules = append(configRules, rules.PKCS8())
	configRules = append(configRules, rules.PyPiUploadToken())
	configRules = append(configRules, rules.RSA())
	configRules = append(configRules, rules.ShopifyAccessToken())
	configRules = append(configRules, rules.ShopifyCustomAccessToken())
	configRules = append(configRules, rules.ShopifyPrivateAppAccessToken())
	configRules = append(configRules, rules.ShopifySharedSecret())
	configRules = append(configRules, rules.SlackAccessToken())
	// TODO figure this one out
	// configRules = append(configRules, rules.SlackWebHook())
	configRules = append(configRules, rules.StripeAccessToken())
	configRules = append(configRules, rules.Twitter())
	configRules = append(configRules, rules.Twilio())

	config := config.Config{}
	config.Rules = configRules
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create("rules.toml")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create rules.toml")
	}
	tmpl.Execute(f, config)

}
