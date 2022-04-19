package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
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
	return validate(r, tps)
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
	return validate(r, tps)
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
	return validate(r, tps)
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
	return validate(r, tps)
}
