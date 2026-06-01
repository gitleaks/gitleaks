package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func PythonJoseJwtEncodeHardcodedKey() *config.Rule {
	r := config.Rule{
		RuleID:      "python-jose-jwt-encode-hardcodedkey",
		Description: "Python Jose library JWT Encode Hardcoded key",
		Regex:       regexp.MustCompile(`(?im)jwt\.encode\([\s]*(?:[^{,]*|\{[^}]*\})[\s]*,[\s]*(?:[^{,]*|\{[^}]*\})[\s]*,[\s]*"([^"]*)"[\s]*,?[\s]*\)`),
		Entropy:     2,
		Path:        regexp.MustCompile(`(?i)\.(py)$`),
		Keywords:    []string{"encode"},
	}

	tps := map[string]string{
		"jwt.py": "custom_token = jwt.encode({\"alg\": \"HS256\", \"typ\": \"JWT\"},{\"user_token\": user_jwt,\"exp\": timestamp().now() + datetime.timedelta(minutes=30),}, \"HARDCODED_KEY\",).decode(\"UTF-8\")",
		// Empty string hardcoded secret
		"jwt2.py": "custom_token = jwt.encode({\"alg\": \"HS256\", \"typ\": \"JWT\"},{\"user_token\": user_jwt,\"exp\": timestamp().now() + datetime.timedelta(minutes=30),}, \"\",).decode(\"UTF-8\")",
	}
	fps := map[string]string{
		"jwt.py": "custom_token = jwt.encode({\"alg\": \"HS256\", \"typ\": \"JWT\"},{\"user_token\": user_jwt,\"exp\": timestamp().now() + datetime.timedelta(minutes=30),}, secret,).decode(\"UTF-8\")",
	}

	return utils.ValidateWithPaths(r, tps, fps)
}

func PythonJoseJwtDecodeHardcodedKey() *config.Rule {
	r := config.Rule{
		RuleID:      "python-jose-jwt-decode-hardcodedkey",
		Description: "Python Jose library JWT Decode Hardcoded key",
		Regex:       regexp.MustCompile(`(?im)jwt\.decode\([\s]*(?:[^{,]*|\{[^}]*\})[\s]*,[\s]*"([^"]*)"[\s]*\)`),
		Entropy:     2,
		Path:        regexp.MustCompile(`(?i)\.(py)$`),
		Keywords:    []string{"decode"},
	}

	tps := map[string]string{
		"jwt.py": "decoded_custom_token = jwt.decode(str(authorization_header), \"HARDCODED_KEY\")",
		// Empty string hardcoded secret
		"jwt2.py": "decoded_custom_token = jwt.decode(str(authorization_header), \"\")",
	}
	fps := map[string]string{
		"jwt.py": "decoded_token = jwt.decode(encoded_jwt, certificate.public_key)",
	}

	return utils.ValidateWithPaths(r, tps, fps)
}