package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func ShopifySharedSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Shopify shared secret",
		RuleID:      "shopify-shared-secret",
		Regex:       regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shpss_"},
	}

	// validate
	tps := []string{"shopifySecret := \"shpss_" + sampleHex32Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate shopify-shared-secret")
		}
	}
	return &r
}

func ShopifyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Shopify access token",
		RuleID:      "shopify-access-token",
		Regex:       regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shpat_"},
	}

	// validate
	tps := []string{"shopifyToken := \"shpat_" + sampleHex32Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate shopify-access-token")
		}
	}
	return &r
}

func ShopifyCustomAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Shopify custom access token",
		RuleID:      "shopify-custom-access-token",
		Regex:       regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shpca_"},
	}

	// validate
	tps := []string{"shopifyToken := \"shpca_" + sampleHex32Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate shopify-custom-access-token")
		}
	}
	return &r
}

func ShopifyPrivateAppAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Shopify private app access token",
		RuleID:      "shopify-private-app-access-token",
		Regex:       regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shppa_"},
	}

	// validate
	tps := []string{"shopifyToken := \"shppa_" + sampleHex32Token + "\""}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate shopify-private-app-access-token")
		}
	}
	return &r
}
