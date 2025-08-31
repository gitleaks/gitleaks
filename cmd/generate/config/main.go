package main

import (
	"os"
	"slices"
	"text/template"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/base"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const (
	templatePath = "rules/config.tmpl"
)

//go:generate go run $GOFILE ../../../config/gitleaks.toml

func main() {
	if len(os.Args) < 2 {
		_, _ = os.Stderr.WriteString("Specify path to the gitleaks.toml config\n")
		os.Exit(2)
	}
	gitleaksConfigPath := os.Args[1]

	configRules := []*config.Rule{
		rules.OnePasswordSecretKey(),
		rules.OnePasswordServiceAccountToken(),
		rules.AdafruitAPIKey(),
		rules.AdobeClientID(),
		rules.AdobeClientSecret(),
		rules.AgeSecretKey(),
		rules.Airtable(),
		rules.AlgoliaApiKey(),
		rules.AlibabaAccessKey(),
		rules.AlibabaSecretKey(),
		rules.AnthropicAdminApiKey(),
		rules.AnthropicApiKey(),
		rules.ArtifactoryApiKey(),
		rules.ArtifactoryReferenceToken(),
		rules.AsanaClientID(),
		rules.AsanaClientSecret(),
		rules.Atlassian(),
		rules.Authress(),
		rules.AWS(),
		rules.AzureActiveDirectoryClientSecret(),
		rules.BitBucketClientID(),
		rules.BitBucketClientSecret(),
		rules.BittrexAccessKey(),
		rules.BittrexSecretKey(),
		rules.Beamer(),
		rules.CodecovAccessToken(),
		rules.CoinbaseAccessToken(),
		rules.ClickHouseCloud(),
		rules.Clojars(),
		rules.CloudflareAPIKey(),
		rules.CloudflareGlobalAPIKey(),
		rules.CloudflareOriginCAKey(),
		rules.CohereAPIToken(),
		rules.ConfluentAccessToken(),
		rules.ConfluentSecretKey(),
		rules.Contentful(),
		rules.CurlHeaderAuth(),
		rules.CurlBasicAuth(),
		rules.Databricks(),
		rules.DatadogtokenAccessToken(),
		rules.DefinedNetworkingAPIToken(),
		rules.DigitalOceanPAT(),
		rules.DigitalOceanOAuthToken(),
		rules.DigitalOceanRefreshToken(),
		rules.DiscordAPIToken(),
		rules.DiscordClientID(),
		rules.DiscordClientSecret(),
		rules.Doppler(),
		rules.DropBoxAPISecret(),
		rules.DropBoxLongLivedAPIToken(),
		rules.DropBoxShortLivedAPIToken(),
		rules.DroneciAccessToken(),
		rules.Duffel(),
		rules.Dynatrace(),
		rules.EasyPost(),
		rules.EasyPostTestAPI(),
		rules.EtsyAccessToken(),
		rules.FacebookSecret(),
		rules.FacebookAccessToken(),
		rules.FacebookPageAccessToken(),
		rules.FastlyAPIToken(),
		rules.FinicityClientSecret(),
		rules.FinicityAPIToken(),
		rules.FlickrAccessToken(),
		rules.FinnhubAccessToken(),
		rules.FlutterwavePublicKey(),
		rules.FlutterwaveSecretKey(),
		rules.FlutterwaveEncKey(),
		rules.FlyIOAccessToken(),
		rules.FrameIO(),
		rules.Freemius(),
		rules.FreshbooksAccessToken(),
		rules.GoCardless(),
		// TODO figure out what makes sense for GCP
		// rules.GCPServiceAccount(),
		rules.GCPAPIKey(),
		rules.GitHubPat(),
		rules.GitHubFineGrainedPat(),
		rules.GitHubOauth(),
		rules.GitHubApp(),
		rules.GitHubRefresh(),
		rules.GitlabCiCdJobToken(),
		rules.GitlabDeployToken(),
		rules.GitlabFeatureFlagClientToken(),
		rules.GitlabFeedToken(),
		rules.GitlabIncomingMailToken(),
		rules.GitlabKubernetesAgentToken(),
		rules.GitlabOauthAppSecret(),
		rules.GitlabPat(),
		rules.GitlabPatRoutable(),
		rules.GitlabPipelineTriggerToken(),
		rules.GitlabRunnerRegistrationToken(),
		rules.GitlabRunnerAuthenticationToken(),
		rules.GitlabRunnerAuthenticationTokenRoutable(),
		rules.GitlabScimToken(),
		rules.GitlabSessionCookie(),
		rules.GitterAccessToken(),
		rules.GrafanaApiKey(),
		rules.GrafanaCloudApiToken(),
		rules.GrafanaServiceAccountToken(),
		rules.HarnessApiKey(),
		rules.HashiCorpTerraform(),
		rules.HashicorpField(),
		rules.Heroku(),
		rules.HerokuV2(),
		rules.HubSpot(),
		rules.HuggingFaceAccessToken(),
		rules.HuggingFaceOrganizationApiToken(),
		rules.Intercom(),
		rules.Intra42ClientSecret(),
		rules.JFrogAPIKey(),
		rules.JFrogIdentityToken(),
		rules.JWT(),
		rules.JWTBase64(),
		rules.KrakenAccessToken(),
		rules.KubernetesSecret(),
		rules.KucoinAccessToken(),
		rules.KucoinSecretKey(),
		rules.LaunchDarklyAccessToken(),
		rules.LinearAPIToken(),
		rules.LinearClientSecret(),
		rules.LinkedinClientID(),
		rules.LinkedinClientSecret(),
		rules.LobAPIToken(),
		rules.LobPubAPIToken(),
		rules.MailChimp(),
		rules.MailGunPubAPIToken(),
		rules.MailGunPrivateAPIToken(),
		rules.MailGunSigningKey(),
		rules.MapBox(),
		rules.MattermostAccessToken(),
		rules.MaxMindLicenseKey(),
		rules.Meraki(),
		rules.MessageBirdAPIToken(),
		rules.MessageBirdClientID(),
		rules.NetlifyAccessToken(),
		rules.NewRelicUserID(),
		rules.NewRelicUserKey(),
		rules.NewRelicBrowserAPIKey(),
		rules.NewRelicInsertKey(),
		rules.Notion(),
		rules.NPM(),
		rules.NugetConfigPassword(),
		rules.NytimesAccessToken(),
		rules.OctopusDeployApiKey(),
		rules.OktaAccessToken(),
		rules.OpenAI(),
		rules.OpenshiftUserToken(),
		rules.PerplexityAPIKey(),
		rules.PlaidAccessID(),
		rules.PlaidSecretKey(),
		rules.PlaidAccessToken(),
		rules.PlanetScalePassword(),
		rules.PlanetScaleAPIToken(),
		rules.PlanetScaleOAuthToken(),
		rules.PostManAPI(),
		rules.Prefect(),
		rules.PrivateAIToken(),
		rules.PrivateKey(),
		rules.PrivateKeyPKCS12File(),
		rules.PulumiAPIToken(),
		rules.PyPiUploadToken(),
		rules.RapidAPIAccessToken(),
		rules.ReadMe(),
		rules.RubyGemsAPIToken(),
		rules.ScalingoAPIToken(),
		rules.SendbirdAccessID(),
		rules.SendbirdAccessToken(),
		rules.SendGridAPIToken(),
		rules.SendInBlueAPIToken(),
		rules.SentryAccessToken(),
		rules.SentryOrgToken(),
		rules.SentryUserToken(),
		rules.SettlemintApplicationAccessToken(),
		rules.SettlemintPersonalAccessToken(),
		rules.SettlemintServiceAccessToken(),
		rules.ShippoAPIToken(),
		rules.ShopifyAccessToken(),
		rules.ShopifyCustomAccessToken(),
		rules.ShopifyPrivateAppAccessToken(),
		rules.ShopifySharedSecret(),
		rules.SidekiqSecret(),
		rules.SidekiqSensitiveUrl(),
		rules.SlackBotToken(),
		rules.SlackUserToken(),
		rules.SlackAppLevelToken(),
		rules.SlackConfigurationToken(),
		rules.SlackConfigurationRefreshToken(),
		rules.SlackLegacyBotToken(),
		rules.SlackLegacyWorkspaceToken(),
		rules.SlackLegacyToken(),
		rules.SlackWebHookUrl(),
		rules.Snyk(),
		rules.Sonar(),
		rules.SourceGraph(),
		rules.StripeAccessToken(),
		rules.SquareAccessToken(),
		rules.SquareSpaceAccessToken(),
		rules.SumoLogicAccessID(),
		rules.SumoLogicAccessToken(),
		rules.TeamsWebhook(),
		rules.TelegramBotToken(),
		rules.TravisCIAccessToken(),
		rules.Twilio(),
		rules.TwitchAPIToken(),
		rules.TwitterAPIKey(),
		rules.TwitterAPISecret(),
		rules.TwitterAccessToken(),
		rules.TwitterAccessSecret(),
		rules.TwitterBearerToken(),
		rules.Typeform(),
		rules.VaultBatchToken(),
		rules.VaultServiceToken(),
		rules.YandexAPIKey(),
		rules.YandexAWSAccessToken(),
		rules.YandexAccessToken(),
		rules.ZendeskSecretKey(),
		rules.GenericCredential(),
		rules.InfracostAPIToken(),
	}

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule, len(configRules))
	for _, rule := range configRules {
		if err := rule.Validate(); err != nil {
			logging.Fatal().Err(err).
				Str("rule-id", rule.RuleID).
				Msg("Failed to validate rule")
		}

		// check if rule is in ruleLookUp
		if _, ok := ruleLookUp[rule.RuleID]; ok {
			logging.Fatal().
				Str("rule-id", rule.RuleID).
				Msg("rule id is not unique")
		}
		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleLookUp[rule.RuleID] = *rule

		// Slices are de-duplicated with a map, every iteration has a different order.
		// This is an awkward workaround.
		for _, allowlist := range rule.Allowlists {
			slices.Sort(allowlist.Commits)
			slices.Sort(allowlist.StopWords)
		}
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create(gitleaksConfigPath)
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to create rules.toml")
	}
	defer f.Close()

	cfg := base.CreateGlobalConfig()
	cfg.Rules = ruleLookUp
	for _, allowlist := range cfg.Allowlists {
		slices.Sort(allowlist.Commits)
		slices.Sort(allowlist.StopWords)
	}
	if err = tmpl.Execute(f, cfg); err != nil {
		logging.Fatal().Err(err).Msg("could not execute template")
	}
}
