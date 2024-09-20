// == WARNING ==
// These functions are used to generate GitLeak's default config.
// You are free to use these in your own project, HOWEVER, no API stability is guaranteed.

package utils

import (
	"fmt"
	"regexp"
	"strings"
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
