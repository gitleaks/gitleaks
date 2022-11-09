package main

import (
	"os"
	"text/template"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	templatePath = "rules/config.tmpl"
)

func main() {
	var configRules []*config.Rule
	configRules = append(configRules, rules.AdafruitAPIKey())
	configRules = append(configRules, rules.AdobeClientID())
	configRules = append(configRules, rules.AdobeClientSecret())
	configRules = append(configRules, rules.AgeSecretKey())
	configRules = append(configRules, rules.Airtable())
	configRules = append(configRules, rules.AlgoliaApiKey())
	configRules = append(configRules, rules.AlibabaAccessKey())
	configRules = append(configRules, rules.AlibabaSecretKey())
	configRules = append(configRules, rules.AsanaClientID())
	configRules = append(configRules, rules.AsanaClientSecret())
	configRules = append(configRules, rules.Atlassian())
	configRules = append(configRules, rules.AWS())
	configRules = append(configRules, rules.BitBucketClientID())
	configRules = append(configRules, rules.BitBucketClientSecret())
	configRules = append(configRules, rules.BittrexAccessKey())
	configRules = append(configRules, rules.BittrexSecretKey())
	configRules = append(configRules, rules.Beamer())
	configRules = append(configRules, rules.CodecovAccessToken())
	configRules = append(configRules, rules.CoinbaseAccessToken())
	configRules = append(configRules, rules.Clojars())
	configRules = append(configRules, rules.ConfluentAccessToken())
	configRules = append(configRules, rules.ConfluentSecretKey())
	configRules = append(configRules, rules.Contentful())
	configRules = append(configRules, rules.Databricks())
	configRules = append(configRules, rules.DatadogtokenAccessToken())
	configRules = append(configRules, rules.DigitalOceanPAT())
	configRules = append(configRules, rules.DigitalOceanOAuthToken())
	configRules = append(configRules, rules.DigitalOceanRefreshToken())
	configRules = append(configRules, rules.DiscordAPIToken())
	configRules = append(configRules, rules.DiscordClientID())
	configRules = append(configRules, rules.DiscordClientSecret())
	configRules = append(configRules, rules.Doppler())
	configRules = append(configRules, rules.DropBoxAPISecret())
	configRules = append(configRules, rules.DropBoxLongLivedAPIToken())
	configRules = append(configRules, rules.DropBoxShortLivedAPIToken())
	configRules = append(configRules, rules.DroneciAccessToken())
	configRules = append(configRules, rules.Duffel())
	configRules = append(configRules, rules.Dynatrace())
	configRules = append(configRules, rules.EasyPost())
	configRules = append(configRules, rules.EasyPostTestAPI())
	configRules = append(configRules, rules.EtsyAccessToken())
	configRules = append(configRules, rules.Facebook())
	configRules = append(configRules, rules.FastlyAPIToken())
	configRules = append(configRules, rules.FinicityClientSecret())
	configRules = append(configRules, rules.FinicityAPIToken())
	configRules = append(configRules, rules.FlickrAccessToken())
	configRules = append(configRules, rules.FinnhubAccessToken())
	configRules = append(configRules, rules.FlutterwavePublicKey())
	configRules = append(configRules, rules.FlutterwaveSecretKey())
	configRules = append(configRules, rules.FlutterwaveEncKey())
	configRules = append(configRules, rules.FrameIO())
	configRules = append(configRules, rules.FreshbooksAccessToken())
	configRules = append(configRules, rules.GoCardless())
	// TODO figure out what makes sense for GCP
	// configRules = append(configRules, rules.GCPServiceAccount())
	configRules = append(configRules, rules.GCPAPIKey())
	configRules = append(configRules, rules.GitHubPat())
	configRules = append(configRules, rules.GitHubFineGrainedPat())
	configRules = append(configRules, rules.GitHubOauth())
	configRules = append(configRules, rules.GitHubApp())
	configRules = append(configRules, rules.GitHubRefresh())
	configRules = append(configRules, rules.Gitlab())
	configRules = append(configRules, rules.GitterAccessToken())
	configRules = append(configRules, rules.GrafanaApiKey())
	configRules = append(configRules, rules.GrafanaCloudApiToken())
	configRules = append(configRules, rules.GrafanaServiceAccountToken())
	configRules = append(configRules, rules.Hashicorp())
	configRules = append(configRules, rules.Heroku())
	configRules = append(configRules, rules.HubSpot())
	configRules = append(configRules, rules.Intercom())
	configRules = append(configRules, rules.JWT())
	configRules = append(configRules, rules.KrakenAccessToken())
	configRules = append(configRules, rules.KucoinAccessToken())
	configRules = append(configRules, rules.KucoinSecretKey())
	configRules = append(configRules, rules.LaunchDarklyAccessToken())
	configRules = append(configRules, rules.LinearAPIToken())
	configRules = append(configRules, rules.LinearClientSecret())
	configRules = append(configRules, rules.LinkedinClientID())
	configRules = append(configRules, rules.LinkedinClientSecret())
	configRules = append(configRules, rules.LobAPIToken())
	configRules = append(configRules, rules.LobPubAPIToken())
	configRules = append(configRules, rules.MailChimp())
	configRules = append(configRules, rules.MailGunPubAPIToken())
	configRules = append(configRules, rules.MailGunPrivateAPIToken())
	configRules = append(configRules, rules.MailGunSigningKey())
	configRules = append(configRules, rules.MapBox())
	configRules = append(configRules, rules.MattermostAccessToken())
	configRules = append(configRules, rules.MessageBirdAPIToken())
	configRules = append(configRules, rules.MessageBirdClientID())
	configRules = append(configRules, rules.NetlifyAccessToken())
	configRules = append(configRules, rules.NewRelicUserID())
	configRules = append(configRules, rules.NewRelicUserKey())
	configRules = append(configRules, rules.NewRelicBrowserAPIKey())
	configRules = append(configRules, rules.NPM())
	configRules = append(configRules, rules.NytimesAccessToken())
	configRules = append(configRules, rules.OktaAccessToken())
	configRules = append(configRules, rules.PlaidAccessID())
	configRules = append(configRules, rules.PlaidSecretKey())
	configRules = append(configRules, rules.PlaidAccessToken())
	configRules = append(configRules, rules.PlanetScalePassword())
	configRules = append(configRules, rules.PlanetScaleAPIToken())
	configRules = append(configRules, rules.PlanetScaleOAuthToken())
	configRules = append(configRules, rules.PostManAPI())
	configRules = append(configRules, rules.Prefect())
	configRules = append(configRules, rules.PrivateKey())
	configRules = append(configRules, rules.PulumiAPIToken())
	configRules = append(configRules, rules.PyPiUploadToken())
	configRules = append(configRules, rules.RapidAPIAccessToken())
	configRules = append(configRules, rules.ReadMe())
	configRules = append(configRules, rules.RubyGemsAPIToken())
	configRules = append(configRules, rules.SendbirdAccessID())
	configRules = append(configRules, rules.SendbirdAccessToken())
	configRules = append(configRules, rules.SendGridAPIToken())
	configRules = append(configRules, rules.SendInBlueAPIToken())
	configRules = append(configRules, rules.SentryAccessToken())
	configRules = append(configRules, rules.ShippoAPIToken())
	configRules = append(configRules, rules.ShopifyAccessToken())
	configRules = append(configRules, rules.ShopifyCustomAccessToken())
	configRules = append(configRules, rules.ShopifyPrivateAppAccessToken())
	configRules = append(configRules, rules.ShopifySharedSecret())
	configRules = append(configRules, rules.SidekiqSecret())
	configRules = append(configRules, rules.SidekiqSensitiveUrl())
	configRules = append(configRules, rules.SlackAccessToken())
	configRules = append(configRules, rules.SlackWebHook())
	configRules = append(configRules, rules.StripeAccessToken())
	configRules = append(configRules, rules.SquareAccessToken())
	configRules = append(configRules, rules.SquareSpaceAccessToken())
	configRules = append(configRules, rules.SumoLogicAccessID())
	configRules = append(configRules, rules.SumoLogicAccessToken())
	configRules = append(configRules, rules.TeamsWebhook())
	configRules = append(configRules, rules.TelegramBotToken())
	configRules = append(configRules, rules.TravisCIAccessToken())
	configRules = append(configRules, rules.Twilio())
	configRules = append(configRules, rules.TwitchAPIToken())
	configRules = append(configRules, rules.TwitterAPIKey())
	configRules = append(configRules, rules.TwitterAPISecret())
	configRules = append(configRules, rules.TwitterAccessToken())
	configRules = append(configRules, rules.TwitterAccessSecret())
	configRules = append(configRules, rules.TwitterBearerToken())
	configRules = append(configRules, rules.Typeform())
	configRules = append(configRules, rules.VaultBatchToken())
	configRules = append(configRules, rules.VaultServiceToken())
	configRules = append(configRules, rules.YandexAPIKey())
	configRules = append(configRules, rules.YandexAWSAccessToken())
	configRules = append(configRules, rules.YandexAccessToken())
	configRules = append(configRules, rules.ZendeskSecretKey())
	configRules = append(configRules, rules.GenericCredential())

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule)
	for _, rule := range configRules {
		// check if rule is in ruleLookUp
		if _, ok := ruleLookUp[rule.RuleID]; ok {
			log.Fatal().Msgf("rule id %s is not unique", rule.RuleID)
		}
		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleLookUp[rule.RuleID] = *rule
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create("../../../config/gitleaks.toml")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create rules.toml")
	}

	if err = tmpl.Execute(f, config.Config{Rules: ruleLookUp}); err != nil {
		log.Fatal().Err(err).Msg("could not execute template")
	}

}
