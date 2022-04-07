package rules

import (
	"regexp"
	"strings"
)

const (
	// case insensitive prefix
	caseInsensitive = `(?i)`

	// identifier prefix (just an ignore group)
	identifierPrefix = `(?:`
	identifierSuffix = `)(?:[0-9a-z\-_\s.]{0,20})(?:'|"){0,1}`

	// commonly used assignment operators or function call
	operator = `(?:=|>|:=|\|\|:|<=|=>|:)`

	// boundaries for the secret
	secretPrefix = `(?:'|\"|\s|=){0,5}(`
	secretSuffix = `)['|\"|\n|\r|\s]`

	hex32 = `[a-f0-9]{32}`
	hex   = `[a-f0-9]`

	sampleHex32Token          = `d0e94828b0549eee7368e53f6cb41d17` // gitleaks:allow
	sampleAlphaNumeric32Token = ``                                 //gitleaks:allow
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
