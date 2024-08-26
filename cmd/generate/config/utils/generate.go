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
	identifierCaseInsensitivePrefix = `[\w.-]{0,50}?(?i:`
	identifierCaseInsensitiveSuffix = `)`
	identifierPrefix                = `[\w.-]{0,50}?(?:`
	identifierSuffix                = `)(?:[\w \t.-]{0,20})(?:\\*['"]{0,3})?[ \t]{0,5}`

	// commonly used assignment operators or function call
	//language=regexp
	operator = `(?:[<>?+]?=|:{1,3}=|>|=>|:|\(|,|\|)`

	// boundaries for the secret
	// \x60 = `
	secretPrefixUnique = `\b(`
	secretPrefix       = `(?:\\*(?:'|")|[\x60\s=|>]){0,5}(`
	secretSuffix       = `)(?:['"\x60\s;\\<,)]|$)`
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

// See: https://github.com/gitleaks/gitleaks/issues/1222
func GenerateSampleSecrets(identifier string, secret string) []string {
	samples := map[string]string{
		// Configuration
		// INI
		"ini - quoted1":   "{i}Token=\"{s}\"",
		"ini - quoted2":   "{i}Token = \"{s}\"",
		"ini - unquoted1": "{i}Token={s}",
		"ini - unquoted2": "{i}Token = {s}",
		// JSON
		"json - string":         "{\n    \"{i}_token\": \"{s}\"\n}",
		"json - escaped string": "\\{\n    \\\"{i}_token\\\": \\\"{s}\\\"\n\\}",
		//TODO: "json - string key/value": "{\n    \"name\": \"{i}_token\",\n    \"value\": \"{s}\"\n}",
		// XML
		"xml - element":           "<{i}Token>{s}</{i}Token>",
		"xml - element multiline": "<{i}Token>\n    {s}\n</{i}Token>",
		//TODO: "xml - attribute": "<entry name=\"{i}Token\" value=\"{s}\" />",
		//TODO: "xml - key/value elements": "<entry>\n  <name=\"{i}Token\" />\n  <value=\"{s}\" />\n</entry>",
		// YAML
		"yaml - singleline - unquoted":     "{i}_token: {s}",
		"yaml - singleline - single quote": "{i}_token: '{s}'",
		"yaml - singleline - double quote": "{i}_token: \"{s}\"",
		"yaml - multiline - literal":       "{i}_token: |\n  {s}",
		"yaml - multiline - folding":       "{i}_token: >\n  {s}",
		//"": "",

		// Programming Languages
		"C#":             `string {i}Token = "{s}";`,
		"go - normal":    `var {i}Token string = "{s}"`,
		"go - short":     `{i}Token := "{s}"`,
		"go - backticks": "{i}Token := `{s}`",
		"java":           "String {i}Token = \"{s}\";",
		//TODO:"kotlin - type":         "var {i}Token: string = \"{s}\"",
		"kotlin - notype":     "var {i}Token = \"{s}\"",
		"php - string concat": `${i}Token .= "{s}"`,
		//TODO: "php - null coalesce":   `${i}Token ??= "{s}"`,
		"python - single quote": "{i}Token = '{s}'",
		"python - double quote": `{i}Token = "{s}"`,
		//"": "",

		// Miscellaneous
		//TODO: "comment - slash": "//{s} is the password",
		//TODO: "comment - slash multiline": "/*{s} is the password",
		//TODO: "comment - hashtag":     "#{s} is the password",
		//TODO: "comment - semicolon":     ";{s} is the password",
		"csv - unquoted": `{i}Token,{s},`,
		"logstash":       "  \"{i}Token\" => \"{s}\"",
		//TODO: "sql - tabular":      "|{s}|",
		//TODO: "sql":      "",

		// Makefile
		// See: https://github.com/gitleaks/gitleaks/pull/1191
		"make - recursive assignment":       "{i}_TOKEN = \"{s}\"",
		"make - simple assignment":          "{i}_TOKEN := \"{s}\"",
		"make - shell assignment":           "{i}_TOKEN ::= \"{s}\"",
		"make - evaluated shell assignment": "{i}_TOKEN :::= \"{s}\"",
		"make - conditional assignment":     "{i}_TOKEN ?= \"{s}\"",
		"make - append":                     "{i}_TOKEN += \"{s}\"",

		//"": "",
	}

	replacer := strings.NewReplacer("{i}", identifier, "{s}", secret)
	cases := make([]string, 0, len(samples))
	for _, v := range samples {
		cases = append(cases, replacer.Replace(v))
	}
	return cases
}
