package rules

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
	// \x60 = `
	secretPrefix = `(?:'|\"|\s|=|\x60){0,5}(`
	secretSuffix = `)['|\"|\n|\r|\s|\x60]`

	// secret regexes
	hex32                  = `[a-f0-9]{32}`
	hex64                  = `[a-f0-9]{64}`
	hex                    = `[a-f0-9]`
	alphaNumeric24         = `[a-z0-9]{24}`
	alphaNumeric30         = `[a-z0-9]{30}`
	alphaNumeric32         = `[a-z0-9]{32}`
	numeric16              = `[0-9]{16}`
	numeric18              = `[0-9]{18}`
	extendedAlphaNumeric32 = `[a-z0-9=_\-]{32}`
	extendedAlphaNumeric64 = `[a-z0-9_\-]{64}`

	// token examples
	sampleHex20Token = `d0e94828b0549eee7368`                                             // gitleaks:allow
	sampleHex32Token = `d0e94828b0549eee7368e53f6cb41d17`                                 // gitleaks:allow
	sampleHex64Token = `d0e94828b0549eee7368e53f6cb41d17d0e94828b0549eee7368e53f6cb41d17` // gitleaks:allow

	sampleAlphaNumeric20Token = `00000AAAAAbbbbb99999`
	sampleAlphaNumeric24Token = `00000AAAAAbbbbb99999qqqq`
	sampleAlphaNumeric30Token = `00000AAAAAbbbbb99999aaaaalllll`
	sampleAlphaNumeric32Token = `00000AAAAAbbbbb99999aaaaalllllzz`
	sampleAlphaNumeric36Token = `00000AAAAAbbbbb9999900000AAAAAbbbbb9`

	sampleNumeric16 = `1111222233334444`
	sampleNumeric18 = `111122223333444422`

	sampleExtendedAlphaNumeric64Token = `00000AAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalllll_-`
	sampleExtendedAlphaNumeric43Token = `00000AAAAAbbbbb99999aaaaallll_--eq-=aa00000`
	sampleExtendedAlphaNumeric32Token = `00000AAAAAbbbbb99999aaaaalllll=_`
	sampleAlphaNumeric60Token         = `00000AAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalll`
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

func generateSampleSecret(identifier string, secret string) string {
	return fmt.Sprintf("%s_api_token = \"%s\"", identifier, secret)
}
