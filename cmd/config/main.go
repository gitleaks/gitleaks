package main

import (
	"fmt"
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
)

// This will create a gitleaks rule that follows similar
// patterns to generic rules. The default capture group for the secret is 1.
func NewRule(identifiers []string, secretRegex string) string {
	var sb strings.Builder
	sb.WriteString(caseInsensitive)
	sb.WriteString(identifierPrefix)
	sb.WriteString(strings.Join(identifiers, "|"))
	sb.WriteString(identifierSuffix)
	sb.WriteString(operator)
	sb.WriteString(secretPrefix)
	sb.WriteString(secretRegex)
	sb.WriteString(secretSuffix)
	_ = regexp.MustCompile(sb.String())
	return sb.String()
}

func main() {
	fmt.Println("heroku: ", NewRule([]string{"heroku"}, "[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"))
	fmt.Println("mailchimp: ", NewRule([]string{"mailchimp"}, hex32+"-us20"))
	fmt.Println("facebook: ", NewRule([]string{"facebook"}, hex32))
	fmt.Println("twitter: ", NewRule([]string{"twitter"}, hex+"{35,44}"))
}
