package base

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"regexp"
)

func CreateGlobalConfig() config.Config {
	return config.Config{
		Title: "gitleaks config",
		Allowlist: config.Allowlist{
			Description: "global allow lists",
			Regexes: []*regexp.Regexp{
				// ----------- General placeholders -----------
				regexp.MustCompile(`(?i)^true|false|null$`),
				// ----------- Interpolated Variables -----------
				// Ansible (https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html)
				regexp.MustCompile(`^\{\{[ \t]*[\w ().|]+[ \t]*}}$`),
				// GitHub Actions
				// https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/store-information-in-variables
				// https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
				regexp.MustCompile(`^\$\{\{[ \t]*((env|github|secrets|vars)(\.[A-Za-z]\w+)+[\w "'&./=|]*)[ \t]*}}$`),
				// NuGet (https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file#using-environment-variables)
				regexp.MustCompile(`^%([A-Z_]+|[a-z_]+)%$`),
				// Urban Code Deploy (https://www.ibm.com/support/pages/replace-token-step-replaces-replacement-values-windows-variables)
				regexp.MustCompile(`^@([A-Z_]+|[a-z_]+)@$`),

				// ----------- Environment Variables -----------
				regexp.MustCompile(`^\$(\d+|{\d+})$`),
				regexp.MustCompile(`^\$([A-Z_]+|[a-z_]+)$`),
				regexp.MustCompile(`^\${([A-Z_]+|[a-z_]+)}$`),
			},
			Paths: []*regexp.Regexp{
				regexp.MustCompile(`gitleaks\.toml`),

				// ----------- Documents and media -----------
				regexp.MustCompile(`(?i)\.(bmp|gif|jpe?g|svg|tiff?)$`),
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

				// ----------- Node.js files -----------
				// Dependencies and lock files.
				regexp.MustCompile(`(^|/)node_modules/.*?$`),
				regexp.MustCompile(`(^|/)package-lock\.json$`),
				regexp.MustCompile(`(^|/)yarn\.lock$`),
				regexp.MustCompile(`(^|/)pnpm-lock\.yaml$`),
				regexp.MustCompile(`(^|/)npm-shrinkwrap\.json$`),
				regexp.MustCompile(`(^|/)bower_components/.*?$`),

				// ----------- Python files -----------
				// Dependencies and lock files.
				regexp.MustCompile(`(^|/)Pipfile\.lock$`),
				regexp.MustCompile(`(^|/)poetry\.lock$`),
				// Virtual environments
				// env/lib/python3.7/site-packages/urllib3/util/url.py
				regexp.MustCompile(`(?i)/?(v?env|virtualenv)/lib/.+$`),
				// /python/3.7.4/Lib/site-packages/dask/bytes/tests/test_bytes_utils.py
				// python/3.7.4/Lib/site-packages/fsspec/utils.py
				// python/2.7.16.32/Lib/bsddb/test/test_dbenv.py
				regexp.MustCompile(`(?i)/?python/[23](\.\d{1,2})+/lib/.+$`),
				// python/lib/python3.8/site-packages/boto3/data/ec2/2016-04-01/resources-1.json
				// python/lib/python3.8/site-packages/botocore/data/alexaforbusiness/2017-11-09/service-2.json
				regexp.MustCompile(`(?i)/?python/lib/python[23](\.\d{1,2})+/.+$`),
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
		},
	}
}
