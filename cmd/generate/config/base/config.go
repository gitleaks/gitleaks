package base

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config"
	"regexp"
	"strings"
)

func CreateGlobalConfig() config.Config {
	return config.Config{
		Title: "gitleaks config",
		Allowlist: config.Allowlist{
			Description: "global allow lists",
			Regexes: []*regexp.Regexp{
				// ----------- General placeholders -----------
				regexp.MustCompile(`(?i)^true|false|null$`),
				// Awkward workaround to detect repeated characters.
				func() *regexp.Regexp {
					var (
						letters  = "abcdefghijklmnopqrstuvwxyz*."
						patterns []string
					)
					for _, char := range letters {
						if char == '*' || char == '.' {
							patterns = append(patterns, fmt.Sprintf("\\%c+", char))
						} else {
							patterns = append(patterns, fmt.Sprintf("%c+", char))
						}
					}
					return regexp.MustCompile("^(?i:" + strings.Join(patterns, "|") + ")$")
				}(),

				// ----------- Environment Variables -----------
				regexp.MustCompile(`^\$(\d+|{\d+})$`),
				regexp.MustCompile(`^\$([A-Z_]+|[a-z_]+)$`),
				regexp.MustCompile(`^\${([A-Z_]+|[a-z_]+)}$`),

				// ----------- Interpolated Variables -----------
				// Ansible (https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html)
				regexp.MustCompile(`^\{\{[ \t]*[\w ().|]+[ \t]*}}$`),
				// GitHub Actions
				// https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables
				// https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
				regexp.MustCompile(`^\$\{\{[ \t]*((env|github|secrets|vars)(\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*}}$`),
				// NuGet (https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file#using-environment-variables)
				regexp.MustCompile(`^%([A-Z_]+|[a-z_]+)%$`),
				// String formatting.
				regexp.MustCompile(`^%[+\-# 0]?[bcdeEfFgGoOpqstTUvxX]$`), // Golang (https://pkg.go.dev/fmt)
				regexp.MustCompile(`^\{\d{0,2}}$`),                       // Python (https://docs.python.org/3/tutorial/inputoutput.html)
				// Urban Code Deploy (https://www.ibm.com/support/pages/replace-token-step-replaces-replacement-values-windows-variables)
				regexp.MustCompile(`^@([A-Z_]+|[a-z_]+)@$`),

				// ----------- Miscellaneous -----------
			},
			Paths: []*regexp.Regexp{
				regexp.MustCompile(`gitleaks\.toml`),

				// ----------- Documents and media -----------
				regexp.MustCompile(`(?i)\.(bmp|gif|jpe?g|svg|tiff?)$`), // Images
				regexp.MustCompile(`\.(eot|[ot]tf|woff2?)$`),           // Fonts
				regexp.MustCompile(`(.*?)(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$`),

				// ----------- Golang files -----------
				regexp.MustCompile(`go\.(mod|sum|work(\.sum)?)$`),
				regexp.MustCompile(`(^|/)vendor/modules\.txt$`),
				regexp.MustCompile(`(^|/)vendor/(github\.com|golang\.org/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)/.*$`),

				// ----------- Java files -----------
				// Gradle
				regexp.MustCompile(`(^|/)gradlew(\.bat)?$`),
				regexp.MustCompile(`(^|/)gradle\.lockfile$`),
				regexp.MustCompile(`(^|/)mvnw(\.cmd)?$`),
				regexp.MustCompile(`(^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$`),

				// ----------- JavaScript files -----------
				// Dependencies and lock files.
				regexp.MustCompile(`(^|/)node_modules/.*?$`),
				regexp.MustCompile(`(^|/)package-lock\.json$`),
				regexp.MustCompile(`(^|/)yarn\.lock$`),
				regexp.MustCompile(`(^|/)pnpm-lock\.yaml$`),
				regexp.MustCompile(`(^|/)npm-shrinkwrap\.json$`),
				regexp.MustCompile(`(^|/)bower_components/.*?$`),
				// TODO: Add more common static assets, such as swagger-ui.
				regexp.MustCompile(`(^|/)(angular|jquery(-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(\.min)?\.js(\.map)?$`),

				// ----------- Python files -----------
				// Dependencies and lock files.
				regexp.MustCompile(`(^|/)(Pipfile|poetry)\.lock$`),
				// Virtual environments
				regexp.MustCompile(`(?i)/?(v?env|virtualenv)/lib(64)?/.+$`),
				regexp.MustCompile(`(?i)(^|/)(lib(64)?/python[23](\.\d{1,2})+/|python/[23](\.\d{1,2})+/lib(64)?/).+$`),
				// dist-info directory (https://py-pkgs.org/04-package-structure.html#building-sdists-and-wheels)
				regexp.MustCompile(`(?i)(^|/)[a-z0-9_.]+-[0-9.]+\.dist-info/.+$`),

				// ----------- Ruby files -----------
				regexp.MustCompile(`(^|/)vendor/(bundle|ruby)/.*?$`),
				regexp.MustCompile(`\.gem$`), // tar archive

				// Misc
				regexp.MustCompile(`verification-metadata.xml`),
				regexp.MustCompile(`Database.refactorlog`),
				//regexp.MustCompile(`vendor`),
			},
			StopWords: []string{
				// ----------- Secrets -----------
				// Checkmarx client secret. (https://github.com/checkmarx-ts/checkmarx-python-sdk/blob/86560f6e2a3e46d16322101294da10d5d190312d/README.md?plain=1#L56)
				"014df517-39d1-4453-b7b3-9930c563627c",
			},
		},
	}
}
