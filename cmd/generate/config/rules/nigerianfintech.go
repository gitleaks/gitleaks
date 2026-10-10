package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func PaystackSecretKey() *config.Rule {
	r := config.Rule{
		RuleID:      "paystack-secret-key",
		Description: "Detected a Paystack secret key that may allow unauthorized payment operations.",
		Regex:       regexp.MustCompile(`(?i)\b(sk_(?:live|test)_[a-z0-9]{40})\b`),
		SecretGroup: 1,
		Entropy:     3.5,
		Keywords:    []string{"sk_live_", "sk_test_"},
	}
	tps := utils.GenerateSampleSecrets("paystack", "sk_live_"+secrets.NewSecret(utils.Hex("40")))
	fps := []string{"sk_live_PLACEHOLDER"}
	return utils.Validate(r, tps, fps)
}

func RemitaAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "remita-api-key",
		Description: "Detected a Remita API key that may expose payment credentials.",
		Regex:       regexp.MustCompile(`(?i)\bremita[_-]?(?:api[_-])?key\s*[:=]\s*["']?([a-z0-9]{40,64})\b`),
		SecretGroup: 1,
		Entropy:     3.5,
		Keywords:    []string{"remita"},
	}
	tps := utils.GenerateSampleSecrets("remita", "remita_api_key="+secrets.NewSecret(utils.Hex("48")))
	fps := []string{"remita_api_key=REDACTED_PLACEHOLDER"}
	return utils.Validate(r, tps, fps)
}

func InterswitchMACKey() *config.Rule {
	r := config.Rule{
		RuleID:      "interswitch-mac-key",
		Description: "Detected a hardcoded Interswitch Webpay MAC key.",
		Regex:       regexp.MustCompile(`(?i)\bmacKey["']?\s*[:=]\s*["']?([0-9a-f]{64})\b`),
		SecretGroup: 1,
		Entropy:     3.5,
		Keywords:    []string{"macKey"},
	}
	tps := utils.GenerateSampleSecrets("interswitch", "macKey="+secrets.NewSecret(utils.Hex("64")))
	fps := []string{"macKey=REDACTED_PLACEHOLDER"}
	return utils.Validate(r, tps, fps)
}

func NigerianBettingJWT() *config.Rule {
	r := config.Rule{
		RuleID:      "nigerian-betting-jwt",
		Description: "Detected a possible hardcoded JWT associated with SportyBet or BetKing.",
		Regex:       regexp.MustCompile(`(?i)\b(?:sportybet|betking)[^\r\n]{0,40}(eyJ[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,})\b`),
		SecretGroup: 1,
		Entropy:     3.5,
		Keywords:    []string{"sportybet", "betking"},
	}
	token := "eyJ" + secrets.NewSecret(utils.AlphaNumericExtendedShort("16")) + "." + secrets.NewSecret(utils.AlphaNumericExtendedShort("16")) + "." + secrets.NewSecret(utils.AlphaNumericExtendedShort("16"))
	tps := utils.GenerateSampleSecrets("sportybet", "sportybet token "+token)
	fps := []string{"sportybet token eyJplaceholder"}
	return utils.Validate(r, tps, fps)
}
