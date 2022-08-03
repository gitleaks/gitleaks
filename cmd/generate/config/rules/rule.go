package rules

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
	identifierPrefix = `(?:`
	identifierSuffix = `)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}`

	// commonly used assignment operators or function call
	operator = `(?:=|>|:=|\|\|:|<=|=>|:)`

	// boundaries for the secret
	// \x60 = `
	secretPrefixUnique = `\b(`
	secretPrefix       = `(?:'|\"|\s|=|\x60){0,5}(`
	secretSuffix       = `)(?:['|\"|\n|\r|\s|\x60|;]|$)`
)

func generateSemiGenericRegex(identifiers []string, secretRegex string) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString(caseInsensitive)
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffix)
	sb.WriteString(operator)
	sb.WriteString(secretPrefix)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func generateUniqueTokenRegex(secretRegex string) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString(caseInsensitive)
	sb.WriteString(secretPrefixUnique)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	return regexp.MustCompile(sb.String())
}

func generateSampleSecret(identifier string, secret string) string {
	return fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
}

func validate(r config.Rule, truePositives []string, falsePositives []string) *config.Rule {
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
			log.Fatal().Msgf("Failed to validate. For rule ID [%s], true positive [%s] was not detected by regexp [%s]", r.RuleID, tp, r.Regex)
		}
	}
	for _, fp := range falsePositives {
		if len(d.DetectString(fp)) != 0 {
			log.Fatal().Msgf("Failed to validate (fp) [%s]", r.RuleID)
		}
	}
	return &r
}

func numeric(size string) string {
	return fmt.Sprintf(`[0-9]{%s}`, size)
}

func hex(size string) string {
	return fmt.Sprintf(`[a-f0-9]{%s}`, size)
}

func alphaNumeric(size string) string {
	return fmt.Sprintf(`[a-z0-9]{%s}`, size)
}

func alphaNumericExtendedShort(size string) string {
	return fmt.Sprintf(`[a-z0-9_-]{%s}`, size)
}

func alphaNumericExtended(size string) string {
	return fmt.Sprintf(`[a-z0-9=_\-]{%s}`, size)
}

func alphaNumericExtendedLong(size string) string {
	return fmt.Sprintf(`[a-z0-9\/=_\+\-]{%s}`, size)
}

func hex8_4_4_4_12() string {
	return `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
}
