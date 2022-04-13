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
	identifierSuffix = `)(?:[0-9a-z\-_\s.]{0,20})(?:'|"){0,1}`

	// commonly used assignment operators or function call
	operator = `(?:=|>|:=|\|\|:|<=|=>|:)`

	// boundaries for the secret
	// \x60 = `
	secretPrefixUnique = `\b(`
	secretPrefix       = `(?:'|\"|\s|=|\x60){0,5}(`
	secretSuffix       = `)['|\"|\n|\r|\s|\x60]`

	// secret regexes
	hex   = `[a-f0-9]`
	hex32 = `[a-f0-9]{32}`
	hex64 = `[a-f0-9]{64}`

	alphaNumeric14 = `[a-z0-9]{14}`
	alphaNumeric15 = `[a-z0-9]{15}`
	alphaNumeric16 = `[a-z0-9]{16}`
	alphaNumeric20 = `[a-z0-9]{20}`
	alphaNumeric24 = `[a-z0-9]{24}`
	alphaNumeric25 = `[a-z0-9]{25}`
	alphaNumeric30 = `[a-z0-9]{30}`
	alphaNumeric32 = `[a-z0-9]{32}`
	alphaNumeric64 = `[a-z0-9]{64}`

	numeric16 = `[0-9]{16}`
	numeric18 = `[0-9]{18}`

	extendedAlphaNumeric32 = `[a-z0-9=_\-]{32}`
	extendedAlphaNumeric60 = `[a-z0-9_\-]{60}`
	extendedAlphaNumeric64 = `[a-z0-9_\-]{64}`

	// token examples
	sampleHex12Token = `b0549eee7368`                                                     // gitleaks:allow
	sampleHex14Token = `b0549eee7368aa`                                                   // gitleaks:allow
	sampleHex16Token = `bbb0549eee7368aa`                                                 // gitleaks:allow
	sampleHex19Token = `d0e94828b0549eee736`                                              // gitleaks:allow
	sampleHex20Token = `d0e94828b0549eee7368`                                             // gitleaks:allow
	sampleHex24Token = `d0e94828b0549eee73688888`                                         // gitleaks:allow
	sampleHex31Token = `d0e94828b0549eee7368e53f6cb41d1`                                  // gitleaks:allow
	sampleHex32Token = `d0e94828b0549eee7368e53f6cb41d17`                                 // gitleaks:allow
	sampleHex34Token = `d0e94828b0549eee7368e53f6cb41d17aa`                               // gitleaks:allow
	sampleHex35Token = `d0e94828b0549eee7368e53f6cb41d17aaa`                              // gitleaks:allow
	sampleHex40Token = `aaaaad0e94828b0549eee7368e53f6cb41d17aaa`                         // gitleaks:allow
	sampleHex48Token = `aaaaaaaaaaaaad0e94828b0549eee7368e53f6cb41d17aaa`                 // gitleaks:allow
	sampleHex64Token = `d0e94828b0549eee7368e53f6cb41d17d0e94828b0549eee7368e53f6cb41d17` // gitleaks:allow

	sampleAlphaNumeric14Token = `00000AAAAAbbbb`
	sampleAlphaNumeric15Token = `00000AAAAAbbbbb`
	sampleAlphaNumeric16Token = `00000AAAAAbbbbbb`
	sampleAlphaNumeric20Token = `00000AAAAAbbbbb99999`
	sampleAlphaNumeric22Token = `00000AAAAAbbbbb99999qq`
	sampleAlphaNumeric24Token = `00000AAAAAbbbbb99999qqqq`
	sampleAlphaNumeric25Token = `00000AAAAAbbbbb99999qqqqq`
	sampleAlphaNumeric27Token = `00000AAAAAbbbbb99999qqqqqqq`
	sampleAlphaNumeric30Token = `00000AAAAAbbbbb99999aaaaalllll`
	sampleAlphaNumeric32Token = `00000AAAAAbbbbb99999aaaaalllllzz`
	sampleAlphaNumeric36Token = `00000AAAAAbbbbb9999900000AAAAAbbbbb9`
	sampleAlphaNumeric40Token = `000000000AAAAAbbbbb9999900000AAAAAbbbbb9`
	sampleAlphaNumeric43Token = `00000AAAAAbbbbb99999aaaaallllpppeqaaaa00000`
	sampleAlphaNumeric54Token = `00000AAAAAbbbbb99999aaaaallllpppeqaaaa00000ttttttttttt`
	sampleAlphaNumeric64Token = `00000AAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalllllll`

	sampleNumeric16 = `1111222233334444`
	sampleNumeric18 = `111122223333444422`

	sampleExtendedAlphaNumeric64Token = `00000AAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalllll_-`
	sampleExtendedAlphaNumeric66Token = `0000000AAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalllll_-`
	sampleExtendedAlphaNumeric59Token = `AAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalllll_-`
	sampleExtendedAlphaNumeric60Token = `AAAAAAbbbbb99999aaaaalllllzz00000AAAAAbbbbb99999aaaaalllll_-`
	sampleExtendedAlphaNumeric40Token = `00AAAAAbbbbb99999aaaaallll_--eq-=aa00000`
	sampleExtendedAlphaNumeric43Token = `00000AAAAAbbbbb99999aaaaallll_--eq-=aa00000`
	sampleExtendedAlphaNumeric32Token = `00000AAAAAbbbbb99999aaaaalllll=_`
	sampleExtendedAlphaNumeric20Token = `bbb99999aaaaalllll=_`
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

func validate(r config.Rule, truePositives []string) *config.Rule {
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range truePositives {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msgf("Failed to validate %s", r.RuleID)
		}
	}
	return &r
}
