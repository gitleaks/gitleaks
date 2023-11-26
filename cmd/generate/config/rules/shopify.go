package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ShopifySharedSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
		RuleID:      "shopify-shared-secret",
		Regex:       regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shpss_"},
	}

	// validate
	tps := []string{"shopifySecret := \"shpss_" + secrets.NewSecret(hex("32")) + "\""}
	return validate(r, tps, nil)
}

func ShopifyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.",
		RuleID:      "shopify-access-token",
		Regex:       regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shpat_"},
	}

	// validate
	tps := []string{"shopifyToken := \"shpat_" + secrets.NewSecret(hex("32")) + "\""}
	return validate(r, tps, nil)
}

func ShopifyCustomAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
		RuleID:      "shopify-custom-access-token",
		Regex:       regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shpca_"},
	}

	// validate
	tps := []string{"shopifyToken := \"shpca_" + secrets.NewSecret(hex("32")) + "\""}
	return validate(r, tps, nil)
}

func ShopifyPrivateAppAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.",
		RuleID:      "shopify-private-app-access-token",
		Regex:       regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`),
		Keywords:    []string{"shppa_"},
	}

	// validate
	tps := []string{"shopifyToken := \"shppa_" + secrets.NewSecret(hex("32")) + "\""}
	return validate(r, tps, nil)
}
