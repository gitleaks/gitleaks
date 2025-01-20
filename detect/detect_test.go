package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const maxDecodeDepth = 8
const configPath = "../testdata/config/"
const repoBasePath = "../testdata/repos/"
const b64TestValues = `
# Decoded
-----BEGIN PRIVATE KEY-----
135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb
u+QDkg0spw==
-----END PRIVATE KEY-----

# Encoded
private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'

# Double Encoded: b64 encoded aws config inside a jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA

# A small secret at the end to make sure that as the other ones above shrink
# when decoded, the positions are taken into consideratoin for overlaps
c21hbGwtc2VjcmV0

# This tests how it handles when the match bounds go outside the decoded value
secret=ZGVjb2RlZC1zZWNyZXQtdmFsdWU=
# The above encoded again
c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFF0ZG1Gc2RXVT0=
`

func TestDetect(t *testing.T) {
	tests := []struct {
		cfgName      string
		baselinePath string
		fragment     Fragment
		// NOTE: for expected findings, all line numbers will be 0
		// because line deltas are added _after_ the finding is created.
		// I.e., if the finding is from a --no-git file, the line number will be
		// increase by 1 in DetectFromFiles(). If the finding is from git,
		// the line number will be increased by the patch delta.
		expectedFindings []report.Finding
		wantError        error
	}{
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OKIA\ // gitleaks:allow"`,
				FilePath: "tmp.go",
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \

		        \"AKIALALEMEL33243OKIA\ // gitleaks:allow"

		        `,
				FilePath: "tmp.go",
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \"AKIALALEMEL33243OKIA\"

		                // gitleaks:allow"

		                `,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OKIA",
					Match:       "AKIALALEMEL33243OKIA",
					File:        "tmp.go",
					Line:        `awsToken := \"AKIALALEMEL33243OKIA\"`,
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Entropy:     3.1464393,
				},
			},
		},
		{
			cfgName: "escaped_character_group",
			fragment: Fragment{
				Raw:      `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "PyPI upload token",
					Secret:      "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Match:       "pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB",
					Line:        `pypi-AgEIcHlwaS5vcmcAAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAA-AAAAAAAAAAB`,
					File:        "tmp.go",
					RuleID:      "pypi-upload-token",
					Tags:        []string{"key", "pypi"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 1,
					EndColumn:   86,
					Entropy:     1.9606875,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        `awsToken := \"AKIALALEMEL33243OLIA\"`,
					File:        "tmp.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Entropy:     3.0841837,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Secret",
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
					Secret:      "cafebabe:deadbeef",
					Line:        `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
					File:        "tmp.sh",
					RuleID:      "sidekiq-secret",
					Tags:        []string{},
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   60,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Secret",
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
					Secret:      "cafebabe:deadbeef",
					File:        "tmp.sh",
					Line:        `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
					RuleID:      "sidekiq-secret",
					Tags:        []string{},
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 21,
					EndColumn:   74,
				},
			},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Sidekiq Sensitive URL",
					Match:       "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:",
					Secret:      "cafeb4b3:d3adb33f",
					File:        "tmp.sh",
					Line:        `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
					RuleID:      "sidekiq-sensitive-url",
					Tags:        []string{},
					Entropy:     2.984234,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   58,
				},
			},
		},
		{
			cfgName: "allow_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
		},
		{
			cfgName: "allow_path",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
		},
		{
			cfgName: "allow_commit",
			fragment: Fragment{
				Raw:       `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath:  "tmp.go",
				CommitSHA: "allowthiscommit",
			},
		},
		{
			cfgName: "entropy_group",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Discord API key",
					Match:       "Discord_Public_Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					File:        "tmp.go",
					RuleID:      "discord-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 7,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Generic API Key",
					Match:       "Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					File:        "tmp.py",
					RuleID:      "generic-api-key",
					Tags:        []string{},
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 22,
					EndColumn:   93,
				},
			},
		},
		{
			cfgName: "path_only",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{
				{
					Description: "Python Files",
					Match:       "file detected: tmp.py",
					File:        "tmp.py",
					RuleID:      "python-files-only",
					Tags:        []string{},
				},
			},
		},
		{
			cfgName: "bad_entropy_group",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
			wantError: fmt.Errorf("discord-api-key: invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: filepath.Join(configPath, "simple.toml"),
			},
		},
		{
			cfgName: "allow_global_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
		},
		{
			cfgName:      "path_only",
			baselinePath: ".baseline.json",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: ".baseline.json",
			},
		},
		{
			cfgName: "base64_encoded",
			fragment: Fragment{
				Raw:      b64TestValues,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{ // Plain text key captured by normal rule
					Description: "Private Key",
					Secret:      "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					Match:       "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					File:        "tmp.go",
					Line:        "\n-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					RuleID:      "private-key",
					Tags:        []string{"key", "private"},
					StartLine:   2,
					EndLine:     5,
					StartColumn: 2,
					EndColumn:   26,
					Entropy:     5.350665,
				},
				{ // Encoded key captured by custom b64 regex rule
					Description: "Private Key",
					Secret:      "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
					Match:       "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
					File:        "tmp.go",
					Line:        "\nprivate_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'",
					RuleID:      "b64-encoded-private-key",
					Tags:        []string{"key", "private"},
					StartLine:   8,
					EndLine:     8,
					StartColumn: 16,
					EndColumn:   207,
					Entropy:     5.3861146,
				},
				{ // Encoded key captured by plain text rule using the decoder
					Description: "Private Key",
					Secret:      "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					Match:       "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					File:        "tmp.go",
					Line:        "\nprivate_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'",
					RuleID:      "private-key",
					Tags:        []string{"key", "private", "decoded:base64", "decode-depth:1"},
					StartLine:   8,
					EndLine:     8,
					StartColumn: 16,
					EndColumn:   207,
					Entropy:     5.350665,
				},
				{ // Encoded AWS config with a access key id inside a JWT
					Description: "AWS IAM Unique Identifier",
					Secret:      "ASIAIOSFODNN7LXM10JI",
					Match:       " ASIAIOSFODNN7LXM10JI",
					File:        "tmp.go",
					Line:        "\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA",
					RuleID:      "aws-iam-unique-identifier",
					Tags:        []string{"aws", "identifier", "decoded:base64", "decode-depth:2"},
					StartLine:   11,
					EndLine:     11,
					StartColumn: 39,
					EndColumn:   344,
					Entropy:     3.6841838,
				},
				{ // Encoded AWS config with a secret access key inside a JWT
					Description: "AWS Secret Access Key",
					Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A",
					Match:       "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A",
					File:        "tmp.go",
					Line:        "\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA",
					RuleID:      "aws-secret-access-key",
					Tags:        []string{"aws", "secret", "decoded:base64", "decode-depth:2"},
					StartLine:   11,
					EndLine:     11,
					StartColumn: 39,
					EndColumn:   344,
					Entropy:     4.721928,
				},
				{ // Encoded Small secret at the end to make sure it's picked up by the decoding
					Description: "Small Secret",
					Secret:      "small-secret",
					Match:       "small-secret",
					File:        "tmp.go",
					Line:        "\nc21hbGwtc2VjcmV0",
					RuleID:      "small-secret",
					Tags:        []string{"small", "secret", "decoded:base64", "decode-depth:1"},
					StartLine:   15,
					EndLine:     15,
					StartColumn: 2,
					EndColumn:   17,
					Entropy:     3.0849626,
				},
				{ // Secret where the decoded match goes outside the encoded value
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nsecret=ZGVjb2RlZC1zZWNyZXQtdmFsdWU=",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:base64", "decode-depth:1"},
					StartLine:   18,
					EndLine:     18,
					StartColumn: 2,
					EndColumn:   36,
					Entropy:     3.3037016,
				},
				{ // Secret where the decoded match goes outside the encoded value and then encoded again
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nc2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFF0ZG1Gc2RXVT0=",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:base64", "decode-depth:2"},
					StartLine:   20,
					EndLine:     20,
					StartColumn: 2,
					EndColumn:   49,
					Entropy:     3.3037016,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s - %s", tt.cfgName, tt.fragment.FilePath), func(t *testing.T) {
			viper.Reset()
			viper.AddConfigPath(configPath)
			viper.SetConfigName(tt.cfgName)
			viper.SetConfigType("toml")
			err := viper.ReadInConfig()
			require.NoError(t, err)

			var vc config.ViperConfig
			err = viper.Unmarshal(&vc)
			require.NoError(t, err)
			cfg, err := vc.Translate()
			cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
			assert.Equal(t, tt.wantError, err)
			d := NewDetector(cfg)
			d.MaxDecodeDepth = maxDecodeDepth
			d.baselinePath = tt.baselinePath

			findings := d.Detect(tt.fragment)
			assert.ElementsMatch(t, tt.expectedFindings, findings)
		})
	}
}

// TestFromGit tests the FromGit function
func TestFromGit(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "small"),
			cfgName: "simple", // the remote url is `git@github.com:gitleaks/test.git`
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 19,
					EndColumn:   38,
					Line:        "\n    awsToken := \"AKIALALEMEL33243OLIA\"",
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					File:        "main.go",
					Date:        "2021-11-02T23:37:53Z",
					Commit:      "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587",
					Author:      "Zachary Rice",
					Email:       "zricer@protonmail.com",
					Message:     "Accidentally add a secret",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587:main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/1b6da43b82b22e4eaa10bcf8ee591e91abbfc587/main.go#L20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   9,
					EndLine:     9,
					StartColumn: 17,
					EndColumn:   36,
					Secret:      "AKIALALEMEL33243OLIA",
					Match:       "AKIALALEMEL33243OLIA",
					Line:        "\n\taws_token := \"AKIALALEMEL33243OLIA\"",
					File:        "foo/foo.go",
					Date:        "2021-11-02T23:48:06Z",
					Commit:      "491504d5a31946ce75e22554cc34203d8e5ff3ca",
					Author:      "Zach Rice",
					Email:       "zricer@protonmail.com",
					Message:     "adding foo package with secret",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "491504d5a31946ce75e22554cc34203d8e5ff3ca:foo/foo.go:aws-access-key:9",
					Link:        "https://github.com/gitleaks/test/blob/491504d5a31946ce75e22554cc34203d8e5ff3ca/foo/foo.go#L9",
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "small"),
			logOpts: "--all foo...",
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   9,
					EndLine:     9,
					StartColumn: 17,
					EndColumn:   36,
					Secret:      "AKIALALEMEL33243OLIA",
					Line:        "\n\taws_token := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Date:        "2021-11-02T23:48:06Z",
					File:        "foo/foo.go",
					Commit:      "491504d5a31946ce75e22554cc34203d8e5ff3ca",
					Author:      "Zach Rice",
					Email:       "zricer@protonmail.com",
					Message:     "adding foo package with secret",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "491504d5a31946ce75e22554cc34203d8e5ff3ca:foo/foo.go:aws-access-key:9",
					Link:        "https://github.com/gitleaks/test/blob/491504d5a31946ce75e22554cc34203d8e5ff3ca/foo/foo.go#L9",
				},
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.cfgName, tt.logOpts}, "/"), func(t *testing.T) {
			viper.AddConfigPath(configPath)
			viper.SetConfigName("simple")
			viper.SetConfigType("toml")
			err := viper.ReadInConfig()
			require.NoError(t, err)

			var vc config.ViperConfig
			err = viper.Unmarshal(&vc)
			require.NoError(t, err)
			cfg, err := vc.Translate()
			require.NoError(t, err)
			detector := NewDetector(cfg)

			var ignorePath string
			info, err := os.Stat(tt.source)
			require.NoError(t, err)

			if info.IsDir() {
				ignorePath = filepath.Join(tt.source, ".gitleaksignore")
			} else {
				ignorePath = filepath.Join(filepath.Dir(tt.source), ".gitleaksignore")
			}
			err = detector.AddGitleaksIgnore(ignorePath)
			require.NoError(t, err)

			gitCmd, err := sources.NewGitLogCmd(tt.source, tt.logOpts)
			require.NoError(t, err)

			remote, err := NewRemoteInfo(scm.NoPlatform, tt.source)
			require.NoError(t, err)

			findings, err := detector.DetectGit(gitCmd, remote)
			require.NoError(t, err)

			for _, f := range findings {
				f.Match = "" // remove lines cause copying and pasting them has some wack formatting
			}
			assert.ElementsMatch(t, tt.expectedFindings, findings)
		})
	}
}
func TestFromGitStaged(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "staged"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   7,
					EndLine:     7,
					StartColumn: 18,
					EndColumn:   37,
					Line:        "\n\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "api/api.go",
					SymlinkFile: "",
					Commit:      "",
					Entropy:     3.0841837,
					Author:      "",
					Email:       "",
					Date:        "0001-01-01T00:00:00Z",
					Message:     "",
					Tags: []string{
						"key",
						"AWS",
					},
					Fingerprint: "api/api.go:aws-access-key:7",
					Link:        "",
				},
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	for _, tt := range tests {

		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, err := vc.Translate()
		require.NoError(t, err)
		detector := NewDetector(cfg)
		err = detector.AddGitleaksIgnore(filepath.Join(tt.source, ".gitleaksignore"))
		require.NoError(t, err)
		gitCmd, err := sources.NewGitDiffCmd(tt.source, true)
		require.NoError(t, err)
		remote, err := NewRemoteInfo(scm.NoPlatform, tt.source)
		require.NoError(t, err)
		findings, err := detector.DetectGit(gitCmd, remote)
		require.NoError(t, err)

		for _, f := range findings {
			f.Match = "" // remove lines cause copying and pasting them has some wack formatting
		}
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

// TestFromFiles tests the FromFiles function
func TestFromFiles(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "nogit"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					File:        "../testdata/repos/nogit/main.go",
					SymlinkFile: "",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/repos/nogit/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", "main.go"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					File:        "../testdata/repos/nogit/main.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/repos/nogit/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:           filepath.Join(repoBasePath, "nogit", "api.go"),
			cfgName:          "simple",
			expectedFindings: []report.Finding{},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", ".env.prod"),
			cfgName: "generic",
			expectedFindings: []report.Finding{
				{
					Description: "Generic API Key",
					StartLine:   4,
					EndLine:     4,
					StartColumn: 5,
					EndColumn:   35,
					Match:       "PASSWORD=8ae31cacf141669ddfb5da",
					Secret:      "8ae31cacf141669ddfb5da",
					Line:        "\nDB_PASSWORD=8ae31cacf141669ddfb5da",
					File:        "../testdata/repos/nogit/.env.prod",
					RuleID:      "generic-api-key",
					Tags:        []string{},
					Entropy:     3.5383105,
					Fingerprint: "../testdata/repos/nogit/.env.prod:generic-api-key:4",
				},
			},
		},
	}

	for _, tt := range tests {
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, _ := vc.Translate()
		detector := NewDetector(cfg)

		var ignorePath string
		info, err := os.Stat(tt.source)
		require.NoError(t, err)

		if info.IsDir() {
			ignorePath = filepath.Join(tt.source, ".gitleaksignore")
		} else {
			ignorePath = filepath.Join(filepath.Dir(tt.source), ".gitleaksignore")
		}
		err = detector.AddGitleaksIgnore(ignorePath)
		require.NoError(t, err)
		detector.FollowSymlinks = true
		paths, err := sources.DirectoryTargets(tt.source, detector.Sema, true, cfg.Allowlist.PathAllowed)
		require.NoError(t, err)
		findings, err := detector.DetectFiles(paths)
		require.NoError(t, err)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func TestDetectWithSymlinks(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "symlinks/file_symlink"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "Asymmetric Private Key",
					StartLine:   1,
					EndLine:     1,
					StartColumn: 1,
					EndColumn:   35,
					Match:       "-----BEGIN OPENSSH PRIVATE KEY-----",
					Secret:      "-----BEGIN OPENSSH PRIVATE KEY-----",
					Line:        "-----BEGIN OPENSSH PRIVATE KEY-----",
					File:        "../testdata/repos/symlinks/source_file/id_ed25519",
					SymlinkFile: "../testdata/repos/symlinks/file_symlink/symlinked_id_ed25519",
					RuleID:      "apkey",
					Tags:        []string{"key", "AsymmetricPrivateKey"},
					Entropy:     3.587164,
					Fingerprint: "../testdata/repos/symlinks/source_file/id_ed25519:apkey:1",
				},
			},
		},
	}

	for _, tt := range tests {
		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		require.NoError(t, err)

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		require.NoError(t, err)
		cfg, _ := vc.Translate()
		detector := NewDetector(cfg)
		detector.FollowSymlinks = true
		paths, err := sources.DirectoryTargets(tt.source, detector.Sema, true, cfg.Allowlist.PathAllowed)
		require.NoError(t, err)
		findings, err := detector.DetectFiles(paths)
		require.NoError(t, err)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func TestDetectRuleAllowlist(t *testing.T) {
	cases := map[string]struct {
		fragment  Fragment
		allowlist config.Allowlist
		expected  []report.Finding
	}{
		// Commit / path
		"commit allowed": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
			},
			allowlist: config.Allowlist{
				Commits: []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
			},
		},
		"path allowed": {
			fragment: Fragment{
				FilePath: "package-lock.json",
			},
			allowlist: config.Allowlist{
				Paths: []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
		},
		"commit AND path allowed": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
				FilePath:  "package-lock.json",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
		},
		"commit AND path NOT allowed": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
				FilePath:  "package.json",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
			expected: []report.Finding{
				{
					StartColumn: 50,
					EndColumn:   60,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "package.json",
					Entropy:     3.095795154571533,
					RuleID:      "test-rule",
				},
			},
		},
		"commit AND path NOT allowed - other conditions": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
				FilePath:  "package-lock.json",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile("password")},
			},
			expected: []report.Finding{
				{
					StartColumn: 50,
					EndColumn:   60,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "package-lock.json",
					Entropy:     3.095795154571533,
					RuleID:      "test-rule",
				},
			},
		},
		"commit OR path allowed": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
				FilePath:  "package-lock.json",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchOr,
				Commits:        []string{"704178e7dca77ff143778a31cff0fc192d59b030"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
		},

		// Regex / stopwords
		"regex allowed": {
			fragment: Fragment{},
			allowlist: config.Allowlist{
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
			},
		},
		"stopwords allowed": {
			fragment: Fragment{},
			allowlist: config.Allowlist{
				StopWords: []string{"summer"},
			},
		},
		"regex AND stopword allowed": {
			fragment: Fragment{},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
				StopWords:      []string{"2024"},
			},
		},
		"regex AND stopword allowed - other conditions": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
				FilePath:  "config.js",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`config.js`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
				StopWords:      []string{"2024"},
			},
		},
		"regex AND stopword NOT allowed - non-git, other conditions": {
			fragment: Fragment{
				FilePath: "config.js",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`config.js`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
				StopWords:      []string{"2024"},
			},
			expected: []report.Finding{
				{
					StartColumn: 50,
					EndColumn:   60,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "config.js",
					Entropy:     3.095795154571533,
					RuleID:      "test-rule",
				},
			},
		},
		"regex AND stopword NOT allowed": {
			fragment: Fragment{},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)winter.+`),
				},
				StopWords: []string{"2024"},
			},
			expected: []report.Finding{
				{
					StartColumn: 50,
					EndColumn:   60,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					Entropy:     3.095795154571533,
					RuleID:      "test-rule",
				},
			},
		},
		"regex AND stopword NOT allowed - other conditions": {
			fragment: Fragment{
				CommitSHA: "a060c9d2d5e90c992763f1bd4c3cd2a6f121241b",
				FilePath:  "config.js",
			},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)winter.+`)},
				StopWords:      []string{"2024"},
			},
			expected: []report.Finding{
				{
					StartColumn: 50,
					EndColumn:   60,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "config.js",
					Entropy:     3.095795154571533,
					RuleID:      "test-rule",
				},
			},
		},
		"regex OR stopword allowed": {
			fragment: Fragment{},
			allowlist: config.Allowlist{
				MatchCondition: config.AllowlistMatchOr,
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
				StopWords:      []string{"winter"},
			},
		},
	}

	raw := `let username = 'james@mail.com';
let password = 'Summer2024!';`
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rule := config.Rule{
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`Summer2024!`),
				Allowlists: []config.Allowlist{
					tc.allowlist,
				},
			}
			d, err := NewDetectorDefaultConfig()
			require.NoError(t, err)

			f := tc.fragment
			f.Raw = raw
			actual := d.detectRule(f, raw, rule, []EncodedSegment{})
			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Errorf("diff: (-want +got)\n%s", diff)
			}
		})
	}
}

func moveDotGit(t *testing.T, from, to string) {
	t.Helper()

	repoDirs, err := os.ReadDir("../testdata/repos")
	require.NoError(t, err)
	for _, dir := range repoDirs {
		if to == ".git" {
			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
			if os.IsNotExist(err) {
				// dont want to delete the only copy of .git accidentally
				continue
			}
			os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
		}
		if !dir.IsDir() {
			continue
		}
		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
		if os.IsNotExist(err) {
			continue
		}

		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
		require.NoError(t, err)
	}
}
