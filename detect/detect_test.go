package detect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/codec"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const maxDecodeDepth = 8
const configPath = "../testdata/config/"
const repoBasePath = "../testdata/repos/"
const archivesBasePath = "../testdata/archives/"
const encodedTestValues = `
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
# when decoded, the positions are taken into consideration for overlaps
c21hbGwtc2VjcmV0

# This tests how it handles when the match bounds go outside the decoded value
secret=ZGVjb2RlZC1zZWNyZXQtdmFsdWUwMA==
# The above encoded again
c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFF0ZG1Gc2RXVT0=

# Confirm you can ignore on the decoded value
password="bFJxQkstejVrZjQtcGxlYXNlLWlnbm9yZS1tZS1YLVhJSk0yUGRkdw=="

# This tests that it can do hex encoded data
secret=6465636F6465642D7365637265742D76616C756576484558

# This tests that it can do percent encoded data
## partial encoded data
secret=decoded-%73%65%63%72%65%74-valuev2
## scattered encoded
secret=%64%65coded-%73%65%63%72%65%74-valuev3

# Test multi levels of encoding where the source is a partal encoding
# it is important that the bounds of the predecessors are properly
# considered
## single percent encoding in the middle of multi layer b64
c2VjcmV0PVpHVmpiMl%4AsWkMxelpXTnlaWFF0ZG1Gc2RXVjJOQT09
## single percent encoding at the beginning of hex
secret%3d6465636F6465642D7365637265742D76616C75657635
## multiple percent encodings in a single layer base64
secret=ZGVjb2%52lZC1zZWNyZXQtdm%46sdWV4ODY=  # ends in x86
## base64 encoded partially percent encoded value
secret=ZGVjb2RlZC0lNzMlNjUlNjMlNzIlNjUlNzQtdmFsdWU=
## one of the lines above that went through... a lot
## and there's surrounding text around it
Look at this value: %4EjMzMjU2NkE2MzZENTYzMDUwNTY3MDQ4%4eTY2RDcwNjk0RDY5NTUzMTRENkQ3ODYx%25%34%65TE3QTQ2MzY1NzZDNjQ0RjY1NTY3MDU5NTU1ODUyNkI2MjUzNTUzMDRFNkU0RTZCNTYzMTU1MzkwQQ== # isn't it crazy?
## Multi percent encode two random characters close to the bounds of the base64
## encoded data to make sure that the bounds are still correctly calculated
secret=ZG%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%322RlZC1zZWNyZXQtd%25%36%64%25%34%36%25%37%33dWU=
## The similar to the above but also touching the edge of the base64
secret=%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34
## The similar to the above but also touching and overlapping the base64
secret%3D%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34
`

var multili = `
username = "admin"



			password = "secret123"
`

func compare(t *testing.T, a, b []report.Finding) {
	if diff := cmp.Diff(a, b,
		cmpopts.SortSlices(func(a, b report.Finding) bool {
			if a.File != b.File {
				return a.File < b.File
			}
			if a.StartLine != b.StartLine {
				return a.StartLine < b.StartLine
			}
			if a.StartColumn != b.StartColumn {
				return a.StartColumn < b.StartColumn
			}
			if a.EndLine != b.EndLine {
				return a.EndLine < b.EndLine
			}
			if a.EndColumn != b.EndColumn {
				return a.EndColumn < b.EndColumn
			}
			if a.RuleID != b.RuleID {
				return a.RuleID < b.RuleID
			}
			return a.Secret < b.Secret
		}),
		cmpopts.IgnoreFields(report.Finding{},
			"Fingerprint", "Author", "Email", "Date", "Message", "Commit", "requiredFindings"),
		cmpopts.EquateApprox(0.0001, 0), // For floating point Entropy comparison
	); diff != "" {
		t.Errorf("findings mismatch (-want +got):\n%s", diff)
	}

}

func TestDetect(t *testing.T) {
	logging.Logger = logging.Logger.Level(zerolog.TraceLevel)
	tests := map[string]struct {
		cfgName      string
		baselinePath string
		fragment     Fragment
		// NOTE: for expected findings, all line numbers will be 0
		// because line deltas are added _after_ the finding is created.
		// I.e., if the finding is from a --no-git file, the line number will be
		// increase by 1 in DetectFromFiles(). If the finding is from git,
		// the line number will be increased by the patch delta.
		expectedFindings  []report.Finding
		wantError         error
		expectedAuxOutput string
	}{
		// General
		"valid allow comment (1)": {
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OKIA\ // gitleaks:allow"`,
				FilePath: "tmp.go",
			},
		},
		"valid allow comment (2)": {
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \

		        \"AKIALALEMEL33243OKIA\ // gitleaks:allow"

		        `,
				FilePath: "tmp.go",
			},
		},
		"invalid allow comment": {
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
		"detect finding - aws": {
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					File:        "tmp.go",
					Line:        `awsToken := \"AKIALALEMEL33243OLIA\"`,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					Entropy:     3.0841837,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 15,
					EndColumn:   34,
					Tags:        []string{"key", "AWS"},
				},
			},
		},
		"detect finding - sidekiq env var": {
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "sidekiq-secret",
					Description: "Sidekiq Secret",
					File:        "tmp.sh",
					Line:        `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
					Secret:      "cafebabe:deadbeef",
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   60,
					Tags:        []string{},
				},
			},
		},
		"detect finding - sidekiq env var, semicolon": {
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "sidekiq-secret",
					Description: "Sidekiq Secret",
					File:        "tmp.sh",
					Line:        `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
					Secret:      "cafebabe:deadbeef",
					Entropy:     2.6098502,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 21,
					EndColumn:   74,
					Tags:        []string{},
				},
			},
		},
		"detect finding - sidekiq url": {
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
				FilePath: "tmp.sh",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "sidekiq-sensitive-url",
					Description: "Sidekiq Sensitive URL",
					File:        "tmp.sh",
					Line:        `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
					Match:       "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:",
					Secret:      "cafeb4b3:d3adb33f",
					Entropy:     2.984234,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 8,
					EndColumn:   58,
					Tags:        []string{},
				},
			},
		},
		"ignore finding - our config file": {
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: filepath.Join(configPath, "simple.toml"),
			},
		},
		"ignore finding - doesn't match path": {
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.go",
			},
		},
		"detect finding - matches path,regex,entropy": {
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "generic-api-key",
					Description: "Generic API Key",
					File:        "tmp.py",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					Match:       "Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 22,
					EndColumn:   93,
					Tags:        []string{},
				},
			},
		},
		"ignore finding - allowlist regex": {
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
		},

		// Rule
		"rule - ignore path": {
			cfgName:      "valid/rule_path_only",
			baselinePath: ".baseline.json",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: ".baseline.json",
			},
		},
		"rule - detect path ": {
			cfgName: "valid/rule_path_only",
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
		"rule - match based on entropy": {
			cfgName: "valid/rule_entropy_group",
			fragment: Fragment{
				Raw: `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"
//const Discord_Public_Key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "discord-api-key",
					Description: "Discord API key",
					File:        "tmp.go",
					Line:        `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					Match:       "Discord_Public_Key = \"e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Entropy:     3.7906237,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 7,
					EndColumn:   93,
					Tags:        []string{},
				},
			},
		},

		// Allowlists
		"global allowlist - ignore regex": {
			cfgName: "valid/allowlist_global_regex",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
		},
		"global allowlist - detect, doesn't match all conditions": {
			cfgName: "valid/allowlist_global_multiple",
			fragment: Fragment{
				Raw: `
const token = "mockSecret";
// const token = "changeit";`,
				FilePath: "config.txt",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "test",
					File:        "config.txt",
					Line:        "\nconst token = \"mockSecret\";",
					Match:       `token = "mockSecret"`,
					Secret:      "mockSecret",
					Entropy:     2.9219282,
					StartLine:   1,
					EndLine:     1,
					StartColumn: 8,
					EndColumn:   27,
					Tags:        []string{},
				},
			},
		},
		"global allowlist - ignore, matches all conditions": {
			cfgName: "valid/allowlist_global_multiple",
			fragment: Fragment{
				Raw:      `token := "mockSecret";`,
				FilePath: "node_modules/config.txt",
			},
		},
		"global allowlist - detect path, doesn't match all conditions": {
			cfgName: "valid/allowlist_global_multiple",
			fragment: Fragment{
				Raw:      `var token = "fakeSecret";`,
				FilePath: "node_modules/config.txt",
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "test",
					File:        "node_modules/config.txt",
					Line:        "var token = \"fakeSecret\";",
					Match:       `token = "fakeSecret"`,
					Secret:      "fakeSecret",
					Entropy:     2.8464394,
					StartLine:   0,
					EndLine:     0,
					StartColumn: 5,
					EndColumn:   24,
					Tags:        []string{},
				},
			},
		},
		"allowlist - ignore commit": {
			cfgName: "valid/allowlist_rule_commit",
			fragment: Fragment{
				Raw:       `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath:  "tmp.go",
				CommitSHA: "allowthiscommit",
			},
		},
		"allowlist - ignore path": {
			cfgName: "valid/allowlist_rule_path",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
		},
		"allowlist - ignore path when extending": {
			cfgName: "valid/allowlist_rule_extend_default",
			fragment: Fragment{
				Raw:      `token = "aebfab88-7596-481d-82e8-c60c8f7de0c0"`,
				FilePath: "path/to/your/problematic/file.js",
			},
		},
		"allowlist - ignore regex": {
			cfgName: "valid/allowlist_rule_regex",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
		},
		"fragment level composite": {
			cfgName: "composite",
			fragment: Fragment{
				Raw: multili,
			},
			expectedFindings: []report.Finding{
				{
					Description: "Primary rule",
					RuleID:      "primary-rule",
					StartLine:   5,
					EndLine:     5,
					StartColumn: 5,
					EndColumn:   26,
					Line:        "\n\t\t\tpassword = \"secret123\"",
					Match:       `password = "secret123"`,
					Secret:      "secret123",
					Entropy:     2.9477028846740723,
					Tags:        []string{},
				},
			},
			expectedAuxOutput: "Required:    username-rule:1:admin\n",
		},
		// Decoding
		"detect encoded": {
			cfgName: "encoded",
			fragment: Fragment{
				Raw:      encodedTestValues,
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
					Secret:      "decoded-secret-value00",
					Match:       "secret=decoded-secret-value00",
					File:        "tmp.go",
					Line:        "\nsecret=ZGVjb2RlZC1zZWNyZXQtdmFsdWUwMA==",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:base64", "decode-depth:1"},
					StartLine:   18,
					EndLine:     18,
					StartColumn: 2,
					EndColumn:   40,
					Entropy:     3.4428623,
				},
				{ // This just confirms that with no allowlist the pattern is detected (i.e. the regex is good)
					Description: "Make sure this would be detected with no allowlist",
					Secret:      "lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw",
					Match:       "password=\"lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw\"",
					File:        "tmp.go",
					Line:        "\npassword=\"bFJxQkstejVrZjQtcGxlYXNlLWlnbm9yZS1tZS1YLVhJSk0yUGRkdw==\"",
					RuleID:      "decoded-password-dont-ignore",
					Tags:        []string{"decode-ignore", "decoded:base64", "decode-depth:1"},
					StartLine:   23,
					EndLine:     23,
					StartColumn: 2,
					EndColumn:   68,
					Entropy:     4.5841837,
				},
				{ // Hex encoded data check
					Description: "Overlapping",
					Secret:      "decoded-secret-valuevHEX",
					Match:       "secret=decoded-secret-valuevHEX",
					File:        "tmp.go",
					Line:        "\nsecret=6465636F6465642D7365637265742D76616C756576484558",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:hex", "decode-depth:1"},
					StartLine:   26,
					EndLine:     26,
					StartColumn: 2,
					EndColumn:   56,
					Entropy:     3.6531072,
				},
				{ // handle partial encoded percent data
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev2",
					Match:       "secret=decoded-secret-valuev2",
					File:        "tmp.go",
					Line:        "\nsecret=decoded-%73%65%63%72%65%74-valuev2",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decode-depth:1"},
					StartLine:   30,
					EndLine:     30,
					StartColumn: 2,
					EndColumn:   42,
					Entropy:     3.4428623,
				},
				{ // handle partial encoded percent data
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev3",
					Match:       "secret=decoded-secret-valuev3",
					File:        "tmp.go",
					Line:        "\nsecret=%64%65coded-%73%65%63%72%65%74-valuev3",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decode-depth:1"},
					StartLine:   32,
					EndLine:     32,
					StartColumn: 2,
					EndColumn:   46,
					Entropy:     3.4428623,
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
				{ // handle encodings that touch eachother
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev5",
					Match:       "secret=decoded-secret-valuev5",
					File:        "tmp.go",
					Line:        "\nsecret%3d6465636F6465642D7365637265742D76616C75657635",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:hex", "decode-depth:2"},
					StartLine:   40,
					EndLine:     40,
					StartColumn: 2,
					EndColumn:   54,
					Entropy:     3.4428623,
				},
				{ // handle partial encoded percent data465642D7365637265742D76616C75657635
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev4",
					Match:       "secret=decoded-secret-valuev4",
					File:        "tmp.go",
					Line:        "\nc2VjcmV0PVpHVmpiMl%4AsWkMxelpXTnlaWFF0ZG1Gc2RXVjJOQT09",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:3"},
					StartLine:   38,
					EndLine:     38,
					StartColumn: 2,
					EndColumn:   55,
					Entropy:     3.4428623,
				},
				{ // multiple percent encodings in a single layer base64
					Description: "Overlapping",
					Secret:      "decoded-secret-valuex86",
					Match:       "secret=decoded-secret-valuex86",
					File:        "tmp.go",
					Line:        "\nsecret=ZGVjb2%52lZC1zZWNyZXQtdm%46sdWV4ODY=  # ends in x86",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:2"},
					StartLine:   42,
					EndLine:     42,
					StartColumn: 2,
					EndColumn:   44,
					Entropy:     3.6381476,
				},
				{ // base64 encoded partially percent encoded value
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nsecret=ZGVjb2RlZC0lNzMlNjUlNjMlNzIlNjUlNzQtdmFsdWU=",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:2"},
					StartLine:   44,
					EndLine:     44,
					StartColumn: 2,
					EndColumn:   52,
					Entropy:     3.3037016,
				},
				{ // one of the lines above that went through... a lot
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nLook at this value: %4EjMzMjU2NkE2MzZENTYzMDUwNTY3MDQ4%4eTY2RDcwNjk0RDY5NTUzMTRENkQ3ODYx%25%34%65TE3QTQ2MzY1NzZDNjQ0RjY1NTY3MDU5NTU1ODUyNkI2MjUzNTUzMDRFNkU0RTZCNTYzMTU1MzkwQQ== # isn't it crazy?",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:hex", "decoded:base64", "decode-depth:7"},
					StartLine:   47,
					EndLine:     47,
					StartColumn: 22,
					EndColumn:   177,
					Entropy:     3.3037016,
				},
				{ // Multi percent encode two random characters close to the bounds of the base64
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nsecret=ZG%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%322RlZC1zZWNyZXQtd%25%36%64%25%34%36%25%37%33dWU=",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:5"},
					StartLine:   50,
					EndLine:     50,
					StartColumn: 2,
					EndColumn:   300,
					Entropy:     3.3037016,
				},
				{ // The similar to the above but also touching the edge of the base64
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nsecret=%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:4"},
					StartLine:   52,
					EndLine:     52,
					StartColumn: 2,
					EndColumn:   86,
					Entropy:     3.3037016,
				},
				{ // The similar to the above but also touching and overlapping the base64
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					File:        "tmp.go",
					Line:        "\nsecret%3D%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:4"},
					StartLine:   54,
					EndLine:     54,
					StartColumn: 2,
					EndColumn:   88,
					Entropy:     3.3037016,
				},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
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

			compare(t, findings, tt.expectedFindings)

			// extremely goofy way to test auxiliary findings
			// capture stdout and print that sonabitch
			// TODO
			if tt.expectedAuxOutput != "" {
				capturedOutput := captureStdout(func() {
					for _, finding := range findings {
						finding.PrintRequiredFindings()
					}
				})

				// Clean up the output for comparison (remove ANSI color codes)
				cleanOutput := stripANSI(capturedOutput)
				expectedClean := stripANSI(tt.expectedAuxOutput)

				assert.Equal(t, expectedClean, cleanOutput, "Auxiliary output should match")
			}

		})
	}
}

func stripANSI(s string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

func captureStdout(f func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// TestFromGit tests the FromGit function
func TestFromGit(t *testing.T) {
	// TODO: Fix this test on windows.
	if runtime.GOOS == "windows" {
		t.Skipf("TODO: this fails on Windows: [git] fatal: bad object refs/remotes/origin/main?")
		return
	}
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
					Entropy:     3.0841837,
					File:        "main.go",
					Date:        "2021-11-02T23:37:53Z",
					Commit:      "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587",
					Author:      "Zachary Rice",
					Email:       "zricer@protonmail.com",
					Message:     "Accidentally add a secret",
					Tags:        []string{"key", "AWS"},
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
		{
			source:  filepath.Join(repoBasePath, "archives"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "main.go.zst",
					Commit:      "db8789716fc664dbce0ed2d492570e92abf717a5",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:10:39Z",
					Message:     "Add main.go.zst",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "db8789716fc664dbce0ed2d492570e92abf717a5:main.go.zst:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/db8789716fc664dbce0ed2d492570e92abf717a5/main.go.zst#L20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.tar!files/api.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.tar!files/api.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.tar!files/main.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.tar!files/main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.zip!files/api.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.zip!files/api.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.zip!files/main.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.zip!files/main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.7z!files/api.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.7z!files/api.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.7z!files/main.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.7z!files/main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.tar.zst!files/api.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.tar.zst!files/api.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.tar.zst!files/main.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.tar.zst!files/main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files/api.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files/api.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files/main.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files/main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files/main.go.xz",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files/main.go.xz:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files/main.go.zst",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files/main.go.zst:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files/main.go.gz",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files/main.go.gz:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.tar.xz!files/api.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.tar.xz!files/api.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "nested.tar.gz!archives/files.tar.xz!files/main.go",
					Commit:      "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68",
					Author:      "Test User",
					Email:       "user@example.com",
					Date:        "2025-05-27T05:08:50Z",
					Message:     "Add nested.tar.gz",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "07d2bd71800f1abf0421abe9bc4a83a6fdca1f68:nested.tar.gz!archives/files.tar.xz!files/main.go:aws-access-key:20",
					Link:        "https://github.com/gitleaks/test/blob/07d2bd71800f1abf0421abe9bc4a83a6fdca1f68/nested.tar.gz",
				},
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.cfgName, tt.source, tt.logOpts}, "/"), func(t *testing.T) {
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
			detector.MaxArchiveDepth = 8

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

			remote := NewRemoteInfo(scm.UnknownPlatform, tt.source)
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
		remote := NewRemoteInfo(scm.UnknownPlatform, tt.source)
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
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/repos/nogit/main.go",
					SymlinkFile: "",
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
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/repos/nogit/main.go",
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
					RuleID:      "generic-api-key",
					Description: "Generic API Key",
					StartLine:   4,
					EndLine:     4,
					StartColumn: 5,
					EndColumn:   35,
					Line:        "\nDB_PASSWORD=8ae31cacf141669ddfb5da",
					Match:       "PASSWORD=8ae31cacf141669ddfb5da",
					Secret:      "8ae31cacf141669ddfb5da",
					File:        "../testdata/repos/nogit/.env.prod",
					Tags:        []string{},
					Entropy:     3.5383105,
					Fingerprint: "../testdata/repos/nogit/.env.prod:generic-api-key:4",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName+" - "+tt.source, func(t *testing.T) {
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

			info, err := os.Stat(tt.source)
			require.NoError(t, err)

			var ignorePath string
			if info.IsDir() {
				ignorePath = filepath.Join(tt.source, ".gitleaksignore")
			} else {
				ignorePath = filepath.Join(filepath.Dir(tt.source), ".gitleaksignore")
			}
			err = detector.AddGitleaksIgnore(ignorePath)
			require.NoError(t, err)

			detector.FollowSymlinks = true
			paths, err := sources.DirectoryTargets(tt.source, detector.Sema, true, cfg.Allowlists)
			require.NoError(t, err)

			findings, err := detector.DetectFiles(paths)
			require.NoError(t, err)

			// TODO: Temporary mitigation.
			// https://github.com/gitleaks/gitleaks/issues/1641
			normalizedFindings := make([]report.Finding, len(findings))
			for i, f := range findings {
				if strings.HasSuffix(f.Line, "\r") {
					f.Line = strings.ReplaceAll(f.Line, "\r", "")
				}
				if strings.HasSuffix(f.Match, "\r") {
					f.EndColumn = f.EndColumn - 1
					f.Match = strings.ReplaceAll(f.Match, "\r", "")
				}
				normalizedFindings[i] = f
			}
			assert.ElementsMatch(t, tt.expectedFindings, normalizedFindings)
		})
	}
}

func TestDetectWithArchives(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:           filepath.Join(archivesBasePath, "this-path-does-not-exist"),
			cfgName:          "archives",
			expectedFindings: []report.Finding{},
		},
		{
			source:  filepath.Join(archivesBasePath, "files"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files/main.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files/main.go.gz",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files/main.go.gz:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files/main.go.xz",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files/main.go.xz:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files/main.go.zst",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files/main.go.zst:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.7z"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.7z!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.7z!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.7z!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.7z!files/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.tar"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.tar!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.tar!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.tar!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.tar!files/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.tar.xz"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.tar.xz!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.tar.xz!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.tar.xz!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.tar.xz!files/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.tar.zst"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.tar.zst!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.tar.zst!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.tar.zst!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.tar.zst!files/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.zip"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.zip!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.zip!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/files.zip!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/files.zip!files/main.go:aws-access-key:20",
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "nested.tar.gz"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.tar!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.tar!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.tar!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.tar!files/main.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.zip!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.zip!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.zip!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.zip!files/main.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.7z!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.7z!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.7z!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.7z!files/main.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.tar.zst!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.tar.zst!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.tar.zst!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.tar.zst!files/main.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files/main.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files/main.go.xz",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files/main.go.xz:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files/main.go.zst",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files/main.go.zst:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files/main.go.gz",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files/main.go.gz:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.tar.xz!files/api.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.tar.xz!files/api.go:aws-access-key:20",
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					StartLine:   20,
					EndLine:     20,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\n\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/archives/nested.tar.gz!archives/files.tar.xz!files/main.go",
					SymlinkFile: "",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "../testdata/archives/nested.tar.gz!archives/files.tar.xz!files/main.go:aws-access-key:20",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName+" - "+tt.source, func(t *testing.T) {
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
			detector.MaxArchiveDepth = 8

			findings, err := detector.DetectSource(
				context.Background(),
				&sources.Files{
					Path:            tt.source,
					Sema:            detector.Sema,
					Config:          &cfg,
					MaxArchiveDepth: detector.MaxArchiveDepth,
				},
			)

			require.NoError(t, err)
			// TODO: Temporary mitigation.
			// https://github.com/gitleaks/gitleaks/issues/1641
			normalizedFindings := make([]report.Finding, len(findings))
			for i, f := range findings {
				if strings.HasSuffix(f.Line, "\r") {
					f.Line = strings.ReplaceAll(f.Line, "\r", "")
				}
				if strings.HasSuffix(f.Match, "\r") {
					f.EndColumn = f.EndColumn - 1
					f.Match = strings.ReplaceAll(f.Match, "\r", "")
				}
				normalizedFindings[i] = f
			}
			assert.ElementsMatch(t, tt.expectedFindings, normalizedFindings)
		})
	}

}

func TestDetectWithSymlinks(t *testing.T) {
	// TODO: Fix this test on windows.
	if runtime.GOOS == "windows" {
		t.Skipf("TODO: this returns no results on windows, I'm not sure why.")
		return
	}

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
					RuleID:      "apkey",
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
		paths, err := sources.DirectoryTargets(tt.source, detector.Sema, true, cfg.Allowlists)
		require.NoError(t, err)

		findings, err := detector.DetectFiles(paths)
		require.NoError(t, err)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func TestDetectRuleAllowlist(t *testing.T) {
	cases := map[string]struct {
		fragment  Fragment
		allowlist *config.Allowlist
		expected  []report.Finding
	}{
		// Commit / path
		"commit allowed": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
			},
			allowlist: &config.Allowlist{
				Commits: []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
			},
		},
		"path allowed": {
			fragment: Fragment{
				FilePath: "package-lock.json",
			},
			allowlist: &config.Allowlist{
				Paths: []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
		},
		"commit AND path allowed": {
			fragment: Fragment{
				CommitSHA: "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
				FilePath:  "package-lock.json",
			},
			allowlist: &config.Allowlist{
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
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
			expected: []report.Finding{
				{
					StartLine:   1,
					EndLine:     1,
					StartColumn: 18,
					EndColumn:   28,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "package.json",
					Commit:      "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
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
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile("password")},
			},
			expected: []report.Finding{
				{
					StartLine:   1,
					EndLine:     1,
					StartColumn: 18,
					EndColumn:   28,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "package-lock.json",
					Commit:      "41edf1f7f612199f401ccfc3144c2ebd0d7aeb48",
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
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchOr,
				Commits:        []string{"704178e7dca77ff143778a31cff0fc192d59b030"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
			},
		},

		// Regex / stopwords
		"regex allowed": {
			fragment: Fragment{},
			allowlist: &config.Allowlist{
				Regexes: []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
			},
		},
		"stopwords allowed": {
			fragment: Fragment{},
			allowlist: &config.Allowlist{
				StopWords: []string{"summer"},
			},
		},
		"regex AND stopword allowed": {
			fragment: Fragment{},
			allowlist: &config.Allowlist{
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
			allowlist: &config.Allowlist{
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
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`config.js`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)summer.+`)},
				StopWords:      []string{"2024"},
			},
			expected: []report.Finding{
				{
					StartLine:   1,
					EndLine:     1,
					StartColumn: 18,
					EndColumn:   28,
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
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)winter.+`),
				},
				StopWords: []string{"2024"},
			},
			expected: []report.Finding{
				{
					StartLine:   1,
					EndLine:     1,
					StartColumn: 18,
					EndColumn:   28,
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
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Commits:        []string{"41edf1f7f612199f401ccfc3144c2ebd0d7aeb48"},
				Paths:          []*regexp.Regexp{regexp.MustCompile(`package-lock.json`)},
				Regexes:        []*regexp.Regexp{regexp.MustCompile(`(?i)winter.+`)},
				StopWords:      []string{"2024"},
			},
			expected: []report.Finding{
				{
					StartLine:   1,
					EndLine:     1,
					StartColumn: 18,
					EndColumn:   28,
					Line:        "let username = 'james@mail.com';\nlet password = 'Summer2024!';",
					Match:       "Summer2024!",
					Secret:      "Summer2024!",
					File:        "config.js",
					Commit:      "a060c9d2d5e90c992763f1bd4c3cd2a6f121241b",
					Entropy:     3.095795154571533,
					RuleID:      "test-rule",
				},
			},
		},
		"regex OR stopword allowed": {
			fragment: Fragment{},
			allowlist: &config.Allowlist{
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
			err := tc.allowlist.Validate()
			require.NoError(t, err)

			rule := config.Rule{
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`Summer2024!`),
				Allowlists: []*config.Allowlist{
					tc.allowlist,
				},
			}
			d, err := NewDetectorDefaultConfig()
			require.NoError(t, err)

			f := tc.fragment
			f.Raw = raw

			actual := d.detectRule(f, raw, rule, []*codec.EncodedSegment{})
			compare(t, tc.expected, actual)
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
			_ = os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
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

// region Windows-specific tests[]
func TestNormalizeGitleaksIgnorePaths(t *testing.T) {
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)

	err = d.AddGitleaksIgnore("../testdata/gitleaksignore/.windowspaths")
	require.NoError(t, err)

	assert.Len(t, d.gitleaksIgnore, 3)
	expected := map[string]struct{}{
		"foo/bar/gitleaks-false-positive.yaml:aws-access-token:4":                                                 {},
		"foo/bar/gitleaks-false-positive.yaml:aws-access-token:5":                                                 {},
		"b55d88dc151f7022901cda41a03d43e0e508f2b7:test_data/test_local_repo_three_leaks.json:aws-access-token:73": {},
	}
	assert.ElementsMatch(t, maps.Keys(d.gitleaksIgnore), maps.Keys(expected))
}

func TestWindowsFileSeparator_RulePath(t *testing.T) {
	unixRule := config.Rule{
		RuleID: "test-rule",
		Path:   regexp.MustCompile(`(^|/)\.m2/settings\.xml`),
	}
	windowsRule := config.Rule{
		RuleID: "test-rule",
		Path:   regexp.MustCompile(`(^|\\)\.m2\\settings\.xml`),
	}
	expected := []report.Finding{
		{
			RuleID: "test-rule",
			Match:  "file detected: .m2/settings.xml",
			File:   ".m2/settings.xml",
		},
	}
	tests := map[string]struct {
		fragment Fragment
		rule     config.Rule
		expected []report.Finding
	}{
		// unix rule
		"unix rule - unix path separator": {
			fragment: Fragment{
				FilePath: `.m2/settings.xml`,
			},
			rule:     unixRule,
			expected: expected,
		},
		"unix rule - windows path separator": {
			fragment: Fragment{
				FilePath:        `.m2/settings.xml`,
				WindowsFilePath: `.m2\settings.xml`,
			},
			rule:     unixRule,
			expected: expected,
		},
		"unix regex+path rule - windows path separator": {
			fragment: Fragment{
				Raw:      `<password>s3cr3t</password>`,
				FilePath: `.m2/settings.xml`,
			},
			rule: config.Rule{
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`<password>(.+?)</password>`),
				Path:   regexp.MustCompile(`(^|/)\.m2/settings\.xml`),
			},
			expected: []report.Finding{
				{
					RuleID:      "test-rule",
					StartColumn: 1,
					EndColumn:   27,
					Line:        "<password>s3cr3t</password>",
					Match:       "<password>s3cr3t</password>",
					Secret:      "s3cr3t",
					Entropy:     2.251629114151001,
					File:        ".m2/settings.xml",
				},
			},
		},

		// windows rule
		"windows rule - unix path separator": {
			fragment: Fragment{
				FilePath: `.m2/settings.xml`,
			},
			rule: windowsRule,
			// This never worked, and continues not to work.
			// Paths should be normalized to use Unix file separators.
			expected: nil,
		},
		"windows rule - windows path separator": {
			fragment: Fragment{
				FilePath:        `.m2/settings.xml`,
				WindowsFilePath: `.m2\settings.xml`,
			},
			rule:     windowsRule,
			expected: expected,
		},
		"windows regex+path rule - windows path separator": {
			fragment: Fragment{
				Raw:             `<password>s3cr3t</password>`,
				FilePath:        `.m2/settings.xml`,
				WindowsFilePath: `.m2\settings.xml`,
			},
			rule: config.Rule{
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`<password>(.+?)</password>`),
				Path:   regexp.MustCompile(`(^|\\)\.m2\\settings\.xml`),
			},
			expected: []report.Finding{
				{
					RuleID:      "test-rule",
					StartColumn: 1,
					EndColumn:   27,
					Line:        "<password>s3cr3t</password>",
					Match:       "<password>s3cr3t</password>",
					Secret:      "s3cr3t",
					Entropy:     2.251629114151001,
					File:        ".m2/settings.xml",
				},
			}},
	}

	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := d.detectRule(test.fragment, test.fragment.Raw, test.rule, []*codec.EncodedSegment{})
			compare(t, test.expected, actual)
		})
	}
}

func TestWindowsFileSeparator_RuleAllowlistPaths(t *testing.T) {
	tests := map[string]struct {
		fragment Fragment
		rule     config.Rule
		expected []report.Finding
	}{
		// unix
		"unix path separator - unix rule - OR allowlist path-only": {
			fragment: Fragment{
				Raw:      `value: "s3cr3t"`,
				FilePath: `ignoreme/unix.txt`,
			},
			rule: config.Rule{
				RuleID: "unix-rule",
				Regex:  regexp.MustCompile(`s3cr3t`),
				Allowlists: []*config.Allowlist{
					{
						Paths: []*regexp.Regexp{regexp.MustCompile(`(^|/)ignoreme(/.*)?$`)},
					},
				},
			},
			expected: nil,
		},
		"unix path separator - windows rule - OR allowlist path-only": {
			fragment: Fragment{
				Raw:      `value: "s3cr3t"`,
				FilePath: `ignoreme/unix.txt`,
			},
			rule: config.Rule{
				RuleID: "windows-rule",
				Regex:  regexp.MustCompile(`s3cr3t`),
				Allowlists: []*config.Allowlist{
					{
						Paths: []*regexp.Regexp{regexp.MustCompile(`(^|\\)ignoreme(\\.*)?$`)},
					},
				},
			},
			// Windows separators in regex don't work for unix.
			expected: []report.Finding{
				{
					RuleID:      "windows-rule",
					StartColumn: 9,
					EndColumn:   14,
					Line:        `value: "s3cr3t"`,
					Match:       `s3cr3t`,
					Secret:      `s3cr3t`,
					File:        "ignoreme/unix.txt",
					Entropy:     2.251629114151001,
				},
			},
		},
		"unix path separator - unix rule - AND allowlist path+stopwords": {
			fragment: Fragment{
				Raw:      `value: "f4k3s3cr3t"`,
				FilePath: `ignoreme/unix.txt`,
			},
			rule: config.Rule{
				RuleID: "unix-rule",
				Regex:  regexp.MustCompile(`value: "[^"]+"`),
				Allowlists: []*config.Allowlist{
					{
						MatchCondition: config.AllowlistMatchAnd,
						Paths:          []*regexp.Regexp{regexp.MustCompile(`(^|/)ignoreme(/.*)?$`)},
						StopWords:      []string{"f4k3"},
					},
				},
			},
			expected: nil,
		},
		"unix path separator - windows rule - AND allowlist path+stopwords": {
			fragment: Fragment{
				Raw:      `value: "f4k3s3cr3t"`,
				FilePath: `ignoreme/unix.txt`,
			},
			rule: config.Rule{
				RuleID: "windows-rule",
				Regex:  regexp.MustCompile(`value: "[^"]+"`),
				Allowlists: []*config.Allowlist{
					{
						MatchCondition: config.AllowlistMatchAnd,
						Paths:          []*regexp.Regexp{regexp.MustCompile(`(^|\\)ignoreme(\\.*)?$`)},
						StopWords:      []string{"f4k3"},
					},
				},
			},
			expected: []report.Finding{
				{
					RuleID:      "windows-rule",
					StartColumn: 1,
					EndColumn:   19,
					Line:        `value: "f4k3s3cr3t"`,
					Match:       `value: "f4k3s3cr3t"`,
					Secret:      `value: "f4k3s3cr3t"`,
					File:        "ignoreme/unix.txt",
					Entropy:     3.892407178878784,
				},
			},
		},

		// windows
		"windows path separator - unix rule - OR allowlist path-only": {
			fragment: Fragment{
				Raw:             `value: "s3cr3t"`,
				FilePath:        `ignoreme/windows.txt`,
				WindowsFilePath: `ignoreme\windows.txt`,
			},
			rule: config.Rule{
				RuleID: "unix-rule",
				Regex:  regexp.MustCompile(`s3cr3t`),
				Allowlists: []*config.Allowlist{
					{
						Paths: []*regexp.Regexp{regexp.MustCompile(`(^|/)ignoreme(/.*)?$`)},
					},
				},
			},
			expected: nil,
		},
		"windows path separator - windows rule - OR allowlist path-only": {
			fragment: Fragment{
				Raw:             `value: "s3cr3t"`,
				FilePath:        `ignoreme/windows.txt`,
				WindowsFilePath: `ignoreme\windows.txt`,
			},
			rule: config.Rule{
				RuleID: "windows-rule",
				Regex:  regexp.MustCompile(`s3cr3t`),
				Allowlists: []*config.Allowlist{
					{
						Paths: []*regexp.Regexp{regexp.MustCompile(`(^|\\)ignoreme(\\.*)?$`)},
					},
				},
			},
			expected: nil,
		},
		"windows path separator - unix rule - AND allowlist path+stopwords": {
			fragment: Fragment{
				Raw:             `value: "f4k3s3cr3t"`,
				FilePath:        `ignoreme/unix.txt`,
				WindowsFilePath: `ignoreme\windows.txt`,
			},
			rule: config.Rule{
				RuleID: "unix-rule",
				Regex:  regexp.MustCompile(`value: "[^"]+"`),
				Allowlists: []*config.Allowlist{
					{
						MatchCondition: config.AllowlistMatchAnd,
						Paths:          []*regexp.Regexp{regexp.MustCompile(`(^|/)ignoreme(/.*)?$`)},
						StopWords:      []string{"f4k3"},
					},
				},
			},
			expected: nil,
		},
		"windows path separator - windows rule - AND allowlist path+stopwords": {
			fragment: Fragment{
				Raw:             `value: "f4k3s3cr3t"`,
				FilePath:        `ignoreme/unix.txt`,
				WindowsFilePath: `ignoreme\windows.txt`,
			},
			rule: config.Rule{
				RuleID: "windows-rule",
				Regex:  regexp.MustCompile(`value: "[^"]+"`),
				Allowlists: []*config.Allowlist{
					{
						MatchCondition: config.AllowlistMatchAnd,
						Paths:          []*regexp.Regexp{regexp.MustCompile(`(^|\\)ignoreme(\\.*)?$`)},
						StopWords:      []string{"f4k3"},
					},
				},
			},
			expected: nil,
		},
	}

	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := d.detectRule(test.fragment, test.fragment.Raw, test.rule, []*codec.EncodedSegment{})
			compare(t, test.expected, actual)
		})
	}
}
