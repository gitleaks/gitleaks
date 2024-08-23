package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const (
	// case insensitive prefix
	caseInsensitive = `(?i)`

	// identifier prefix (just an ignore group)
	identifierCaseInsensitivePrefix = `(?i:`
	identifierCaseInsensitiveSuffix = `)`
	identifierPrefix                = `(?:`
	identifierSuffix                = `)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}`

	// commonly used assignment operators or function call
	operator = `(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)`

	// boundaries for the secret
	// \x60 = `
	secretPrefixUnique = `\b(`
	secretPrefix       = `(?:'|\"|\s|=|\x60){0,5}(`
	secretSuffix       = `)(?:['|\"|\n|\r|\s|\x60|;]|$)`
)

func GenerateSemiGenericRegex(identifiers []string, secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	// The identifiers should always be case-insensitive.
	// This is inelegant but prevents an extraneous `(?i:)` from being added to the pattern; it could be removed.
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
		writeIdentifiers(&sb, identifiers)
	} else {
		sb.WriteString(identifierCaseInsensitivePrefix)
		writeIdentifiers(&sb, identifiers)
		sb.WriteString(identifierCaseInsensitiveSuffix)
	}
	sb.WriteString(operator)
	sb.WriteString(secretPrefix)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func writeIdentifiers(sb *strings.Builder, identifiers []string) {
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffix)
}

func GenerateUniqueTokenRegex(secretRegex string, isCaseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	if isCaseInsensitive {
		sb.WriteString(caseInsensitive)
	}
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func GenerateSampleSecret(identifier string, secret string) string {
	return fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
}

func Validate(r config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	// normalize keywords like in the config package
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	d := detect.NewDetector(config.Config{
		Rules:    rules,
		Keywords: keywords,
	})
	for _, tp := range truePositives {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. True positive was not detected by regex.")
		}
	}
	for _, fp := range falsePositives {
		if len(d.DetectString(fp)) != 0 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. False positive was detected by regex.")
		}
	}
	return &r
}

func ValidateWithPaths(r config.Rule, truePositives map[string]string, falsePositives map[string]string) *config.Rule {
	var keywords []string
	for _, k := range r.Keywords {
		keywords = append(keywords, strings.ToLower(k))
	}
	r.Keywords = keywords

	rules := make(map[string]config.Rule)
	rules[r.RuleID] = r
	d := detect.NewDetector(config.Config{
		Rules:    rules,
		Keywords: keywords,
	})
	for path, tp := range truePositives {
		f := detect.Fragment{Raw: tp, FilePath: path}
		if len(d.Detect(f)) != 1 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. True positive was not detected by regex and/or path.")
		}
	}
	for path, fp := range falsePositives {
		f := detect.Fragment{Raw: fp, FilePath: path}
		if len(d.Detect(f)) != 0 {
			log.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. False positive was detected by regex and/or path.")
		}
	}
	return &r
}

func Numeric(size string) string {
	return fmt.Sprintf(`[0-9]{%s}`, size)
}

func Hex(size string) string {
	return fmt.Sprintf(`[a-f0-9]{%s}`, size)
}

func AlphaNumeric(size string) string {
	return fmt.Sprintf(`[a-z0-9]{%s}`, size)
}

func AlphaNumericExtendedShort(size string) string {
	return fmt.Sprintf(`[a-z0-9_-]{%s}`, size)
}

func AlphaNumericExtended(size string) string {
	return fmt.Sprintf(`[a-z0-9=_\-]{%s}`, size)
}

func AlphaNumericExtendedLong(size string) string {
	return fmt.Sprintf(`[a-z0-9\/=_\+\-]{%s}`, size)
}

func Hex8_4_4_4_12() string {
	return `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
}
