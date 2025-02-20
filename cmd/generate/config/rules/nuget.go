package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func NugetConfigPassword() *config.Rule {
	r := config.Rule{
		Description: "Identified a password within a Nuget config file, potentially compromising package management access.",
		RuleID:      "nuget-config-password",
		Regex:       regexp.MustCompile(`(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`),
		Path:        regexp.MustCompile(`(?i)nuget\.config$`),
		Keywords:    []string{"<add key="},
		Entropy:     1,
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					// samples from https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file
					regexp.MustCompile(`33f!!lloppa`),
					regexp.MustCompile(`hal\+9ooo_da!sY`),
					// exclude environment variables
					regexp.MustCompile(`^\%\S.*\%$`),
				},
			},
		},
	}

	tps := map[string]string{
		"nuget.config": `<add key="Password" value="CleartextPassword1" />`,
		"Nuget.config": `<add key="ClearTextPassword" value="CleartextPassword1" />`,
		"Nuget.Config": `<add key="ClearTextPassword" value="TestSourcePassword" />`,
		"Nuget.COnfig": `<add key="ClearTextPassword" value="TestSource-Password" />`,
		"Nuget.CONfig": `<add key="ClearTextPassword" value="TestSource%Password" />`,
		"Nuget.CONFig": `<add key="ClearTextPassword" value="TestSource%Password%" />`,
	}

	fps := map[string]string{
		"some.xml":     `<add key="Password" value="CleartextPassword1" />`,            // wrong filename
		"nuget.config": `<add key="ClearTextPassword" value="XXXXXXXXXXX" />`,          // low entropy
		"Nuget.config": `<add key="ClearTextPassword" value="abc" />`,                  // too short
		"Nuget.Config": `<add key="ClearTextPassword" value="%TestSourcePassword%" />`, // environment variable
		"NUget.Config": `<add key="ClearTextPassword" value="33f!!lloppa" />`,          // known sample
		"NUGet.Config": `<add key="ClearTextPassword" value="hal+9ooo_da!sY" />`,       // known sample
	}
	return utils.ValidateWithPaths(r, tps, fps)
}
