// Package rules — community contribution.
//
// sealed_env.go — secrets emitted or consumed by sealed-env, an
// open-source cross-stack secret management library for Node.js
// and Java, published on npm + Maven Central.
//
//	Project: https://github.com/davidalmeidac/sealed-env
//	Canonical pattern spec:
//	  https://github.com/davidalmeidac/sealed-env/blob/main/SECRET-PATTERNS.md
//
// Six rules are registered:
//
//	SealedEnvCredentialToken    SE-T1 — sealed_env_<mode>_<cksum>_<payload>
//	SealedEnvUnsealToken        SE-T2 — usl_<header>.<payload>.<sig>
//	SealedEnvMasterKey          SE-K1 — SEALED_ENV_KEY=<64 hex>
//	SealedEnvSigningKey         SE-K2 — SEALED_ENV_SIGNING_KEY=<64 hex>
//	SealedEnvTotpSecret         SE-K3 — SEALED_ENV_TOTP_SECRET=<base32>
//	SealedEnvTotpOtpauthUri     SE-K3-URI — otpauth://totp/...?secret=<base32>
//
// Reference: CVE-2026-45091 (self-disclosed by the sealed-env
// maintainer, CVSS 9.1) motivates first-class detection of these
// tokens — once an operator's credential leaks publicly, every
// other defense the library ships becomes irrelevant.

package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// SealedEnvCredentialToken — SE-T1
//
// Format: sealed_env_<mode>_<cksum>_<payload>
//   - mode:    single letter b|t|e|u|d
//   - cksum:   4 lowercase hex chars (2-byte HMAC)
//   - payload: base64url-encoded CBOR, 20-500 chars
//
// May carry the master key, the master+signing keys, or — in versions
// affected by CVE-2026-45091 — the literal TOTP secret. Treat as
// critical-severity leak.
func SealedEnvCredentialToken() *config.Rule {
	r := config.Rule{
		RuleID:      "sealed-env-credential-token",
		Description: "Discovered a sealed-env credential token (carries master key, signing key, or — in legacy enterprise mode — TOTP secret).",
		Regex:       utils.GenerateUniqueTokenRegex(`sealed_env_[btued]_[0-9a-fA-F]{4}_[A-Za-z0-9_-]{20,500}`, true),
		Entropy:     3.5,
		Keywords:    []string{"sealed_env_"},
	}

	// Generate realistic-looking sealed-env credential tokens. The payload
	// is real random base64url-shaped material so entropy validation passes.
	tps := utils.GenerateSampleSecrets(
		"sealedEnvToken",
		"sealed_env_b_"+secrets.NewSecret(`[0-9a-f]{4}`)+"_"+secrets.NewSecret(utils.AlphaNumericExtendedShort("60")),
	)
	tps = append(tps,
		utils.GenerateSampleSecrets("sealedEnvToken",
			"sealed_env_t_"+secrets.NewSecret(`[0-9a-f]{4}`)+"_"+secrets.NewSecret(utils.AlphaNumericExtendedShort("80")))...)
	tps = append(tps,
		utils.GenerateSampleSecrets("sealedEnvToken",
			"sealed_env_e_"+secrets.NewSecret(`[0-9a-f]{4}`)+"_"+secrets.NewSecret(utils.AlphaNumericExtendedShort("120")))...)

	fps := []string{
		`sealed_env_x_abcd_payloadbase64urlencodedhere1234567890ABCDEFGHIJKLMN`, // invalid mode 'x'
		`sealed_env_b_GGGG_oWFtWCCh7VbT8ZuKMQpA3kjY9xWmF2Lr-c4dGzN5oeVRsHnIxQp`, // invalid checksum chars
		`sealed_env_b_c0dd_short`,             // payload too short
		`sealed-env-b-c0dd-payload`,           // dash separators (wrong format)
		`sealed_env_<mode>_<cksum>_<payload>`, // documentation placeholder
	}
	return utils.Validate(r, tps, fps)
}

// SealedEnvUnsealToken — SE-T2
//
// Format: usl_<header>.<payload>.<sig>
//   - JWS shape (HS256)
//   - Each section is base64url, 40-400 chars
//   - Payload contains a salt-bound HMAC derivative of the operator's
//     TOTP secret — the raw TOTP secret never appears in the token
//     (post-CVE-2026-45091 patch).
//
// Single-use within a short TTL (typically 30-60s). A leak within the
// TTL window grants one decrypt attempt.
func SealedEnvUnsealToken() *config.Rule {
	r := config.Rule{
		RuleID:      "sealed-env-unseal-token",
		Description: "Discovered a sealed-env unseal token (TOTP-bound, HS256 JWS).",
		Regex:       utils.GenerateUniqueTokenRegex(`usl_[A-Za-z0-9_-]{40,200}\.[A-Za-z0-9_-]{40,400}\.[A-Za-z0-9_-]{40,100}`, true),
		Entropy:     3.5,
		Keywords:    []string{"usl_"},
	}

	tps := utils.GenerateSampleSecrets(
		"sealedEnvUnsealToken",
		"usl_"+secrets.NewSecret(utils.AlphaNumericExtendedShort("50"))+
			"."+secrets.NewSecret(utils.AlphaNumericExtendedShort("200"))+
			"."+secrets.NewSecret(utils.AlphaNumericExtendedShort("43")),
	)

	fps := []string{
		`usl_short`,                                  // too short, no dots
		`usl_a.b.c`,                                  // parts too short
		`usl_aaaaaaaa.bbbbbbbb.cccccccc`,             // parts still too short
		`USL_eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzZWFsZWQtZW52In0.QQ`, // wrong case
		`https://example.com/api/musl_test_endpoint`,             // not at boundary (URL path)
	}
	return utils.Validate(r, tps, fps)
}

// SealedEnvMasterKey — SE-K1
//
// 32-byte master key (64 hex chars) in the SEALED_ENV_KEY env var.
// Sufficient alone to decrypt any file sealed in basic mode.
//
// Note on the regex: Go's regexp package uses RE2, which doesn't
// support negative lookahead. We use \b (word boundary) after the
// hex run to ensure the hex sequence ends — equivalent to the
// negative-lookahead form in SECRET-PATTERNS.md.
func SealedEnvMasterKey() *config.Rule {
	r := config.Rule{
		RuleID:      "sealed-env-master-key",
		Description: "Discovered a sealed-env master key (32-byte hex in SEALED_ENV_KEY).",
		Regex:       utils.GenerateSemiGenericRegex([]string{"SEALED_ENV_KEY"}, `[0-9a-fA-F]{64}\b`, true),
		Entropy:     3.5,
		Keywords:    []string{"SEALED_ENV_KEY"},
	}

	tps := utils.GenerateSampleSecrets("SEALED_ENV_KEY", secrets.NewSecret(utils.Hex("64")))
	fps := []string{
		`SEALED_ENV_KEY=<your_key_here>`,
		`SEALED_ENV_KEY=changeme`,
		`SEALED_ENV_KEY=abc`, // too short
		`SEALED_ENV_KEY=ghijklmnopqrstuvghijklmnopqrstuvghijklmnopqrstuvghijklmnopqrstuv`, // not hex
		`SEALED_ENV_KEY=$MASTER_KEY`,                                                    // shell substitution
		`SEALED_ENV_KEY="$(< /run/secrets/master.hex)"`,                                  // command substitution
	}
	return utils.Validate(r, tps, fps)
}

// SealedEnvSigningKey — SE-K2
//
// 32-byte HMAC signing key (64 hex chars) used in team and enterprise
// modes. Combined with a leaked master key, allows tampering.
func SealedEnvSigningKey() *config.Rule {
	r := config.Rule{
		RuleID:      "sealed-env-signing-key",
		Description: "Discovered a sealed-env signing key (32-byte hex in SEALED_ENV_SIGNING_KEY).",
		Regex:       utils.GenerateSemiGenericRegex([]string{"SEALED_ENV_SIGNING_KEY"}, `[0-9a-fA-F]{64}\b`, true),
		Entropy:     3.5,
		Keywords:    []string{"SEALED_ENV_SIGNING_KEY"},
	}

	tps := utils.GenerateSampleSecrets("SEALED_ENV_SIGNING_KEY", secrets.NewSecret(utils.Hex("64")))
	fps := []string{
		`SEALED_ENV_SIGNING_KEY=<sign_with_this>`,
		`SEALED_ENV_SIGNING_KEY=baba`, // too short
		`SEALED_ENV_SIGNING_KEY=$SIGN_KEY`,
	}
	return utils.Validate(r, tps, fps)
}

// SealedEnvTotpSecret — SE-K3
//
// Base32-encoded TOTP shared secret (RFC 6238), 16-64 chars.
// Combined with the master key, defeats enterprise mode 2FA.
func SealedEnvTotpSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "sealed-env-totp-secret",
		Description: "Discovered a sealed-env TOTP secret (base32 in SEALED_ENV_TOTP_SECRET).",
		Regex:       utils.GenerateSemiGenericRegex([]string{"SEALED_ENV_TOTP_SECRET"}, `[A-Z2-7]{16,64}={0,6}\b`, true),
		Entropy:     3.0,
		Keywords:    []string{"SEALED_ENV_TOTP_SECRET"},
	}

	// Use a base32 alphabet generator: A-Z + 2-7 only.
	tps := utils.GenerateSampleSecrets("SEALED_ENV_TOTP_SECRET", secrets.NewSecret(`[A-Z2-7]{32}`))
	fps := []string{
		`SEALED_ENV_TOTP_SECRET=<paste_otpauth_secret_here>`,
		`SEALED_ENV_TOTP_SECRET=ABCDEF`, // too short
		// Note: gitleaks applies `(?i)` globally, so lowercase base32 will
		// match too — that's actually desirable behavior here (a lowercase
		// value looks like base32 enough to be worth flagging).
	}
	return utils.Validate(r, tps, fps)
}

// SealedEnvTotpOtpauthUri — SE-K3-URI
//
// otpauth:// URI carrying the TOTP secret. Same severity as SE-K3 —
// it's the same secret in a different encoding. Easy to leak via
// QR-render screenshots, paste-into-chat, and shared docs.
func SealedEnvTotpOtpauthUri() *config.Rule {
	r := config.Rule{
		RuleID:      "sealed-env-totp-otpauth-uri",
		Description: "Discovered an otpauth:// URI containing a TOTP secret (sealed-env enterprise mode).",
		Regex:       utils.GenerateUniqueTokenRegex(`otpauth://totp/[^?\s]*\?[^"\s]*secret=[A-Z2-7]{16,64}={0,6}[^"\s]*`, true),
		Entropy:     3.0,
		Keywords:    []string{"otpauth://"},
	}

	tps := utils.GenerateSampleSecrets(
		"sealedEnvOtpauthUri",
		"otpauth://totp/sealed-env:operator@example.com?secret="+
			secrets.NewSecret(`[A-Z2-7]{32}`)+
			"&issuer=sealed-env",
	)

	fps := []string{
		`otpauth://totp/MyApp:user@example.com?issuer=MyApp`,       // no secret param
		`otpauth://hotp/example?secret=JBSWY3DPEHPK3PXP&counter=0`, // hotp, not totp
	}
	return utils.Validate(r, tps, fps)
}
