package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// NuntiqAPIKey detects Nuntiq credentials: customer API keys (nuntiq_ck_), partner API keys
// (nuntiq_pk_) and rotation secrets (nuntiq_rs_). Each carries the environment (live, test, dev),
// an 8-hex key id, 43 base64url random characters and a 6-character base62 CRC32 checksum of the
// random part.
func NuntiqAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "nuntiq-api-key",
		Description: "Uncovered a Nuntiq API credential (customer API key, partner API key or rotation secret), which could give access to a tenant's invoice, supplier and payment data.",
		Regex:       utils.GenerateUniqueTokenRegex(`nuntiq_(?:ck|pk|rs)_(?:live|test|dev)_[0-9a-f]{8}_[A-Za-z0-9_-]{43}[0-9A-Za-z]{6}`, false),
		Entropy:     3.5,
		Keywords:    []string{"nuntiq_ck_", "nuntiq_pk_", "nuntiq_rs_"},
	}

	// validate
	tps := []string{
		// Format-valid credentials with a correct checksum that were never issued.
		`NUNTIQ_API_KEY=nuntiq_ck_live_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C`,
		`"X-API-Key": "nuntiq_pk_live_326e932b_pcvLCgsshxMD84d2YyG8mqrkXIcXBG0-YhknB7Q6zDU3ggTr8"`,
		`rotation_secret: nuntiq_rs_live_21de8760_SqPffdMtVohhIsr6xV3cb9KQeXZ33W2DY2jtbXBeY0Q2ESzMW`,
		`curl -H "X-API-Key: nuntiq_ck_test_e8bcfd3f_IwlPImwzSnmfIZ7hFLDQea4xhIznzZvKRPzBU5D0WSQ457xL8"`,
		utils.GenerateSampleSecret("nuntiq", "nuntiq_ck_dev_"+secrets.NewSecret(utils.Hex("8"))+"_"+secrets.NewSecret(`[A-Za-z0-9_-]{43}`)+secrets.NewSecret(`[0-9A-Za-z]{6}`)),
	}
	fps := []string{
		// Documentation placeholders and shortened display forms.
		`nuntiq_ck_live_1a2b3c4d...wXyZ`,
		`nuntiq_rs_live_7c8d9e0f_Yh2k...`,
		`nuntiq_ck_live_<id>_<random><checksum>`,
		// Wrong kind or environment word.
		`nuntiq_xk_live_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C`,
		`nuntiq_ck_prod_1787e770_Cx3BT1zw4XhBmOwTNnTzqXVssmZWnD8n-XosQLWqXJI0fil7C`,
	}
	return utils.Validate(r, tps, fps)
}
