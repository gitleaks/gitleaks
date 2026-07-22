package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteGitlabCodeQuality(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
		cfgName        string
	}{
		{
			cfgName:        "simple",
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "gitlab_code_quality_simple.json"),
			findings: []Finding{
				{
					RuleID:      "test-rule",
					Description: "A test rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   17,
					EndLine:     17,
					StartColumn: 5,
					EndColumn:   12,
					File:        "auth.py",
					Commit:      "0000000000000000",
					Fingerprint: "0000000000000000:auth.py:test-rule:17",
				},
			},
		},
		{
			cfgName:        "empty",
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "gitlab_code_quality_empty.json"),
			findings:       []Finding{},
		},
	}

	for _, test := range tests {
		t.Run(test.cfgName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
			require.NoError(t, err)
			defer tmpfile.Close()

			reporter := GitlabCodeQualityReporter{}
			err = reporter.Write(tmpfile, test.findings)
			require.NoError(t, err)
			assert.FileExists(t, tmpfile.Name())

			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)

			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)

			wantStr := lineEndingReplacer.Replace(string(want))
			gotStr := lineEndingReplacer.Replace(string(got))
			assert.Equal(t, wantStr, gotStr)
		})
	}
}

func TestGitlabCodeQualityFingerprintFallback(t *testing.T) {
	// Without a Fingerprint field set, the reporter should still emit a
	// stable, non-empty identifier derived from the finding's identifying
	// fields.
	f := Finding{
		RuleID:      "test-rule",
		File:        "auth.py",
		Commit:      "abc",
		StartLine:   17,
		StartColumn: 5,
		Secret:      "shhh",
	}
	first := gitlabCQFingerprint(f)
	second := gitlabCQFingerprint(f)
	assert.NotEmpty(t, first)
	assert.Equal(t, first, second, "fingerprint must be stable for the same finding")

	// Different finding -> different fingerprint.
	f2 := f
	f2.StartLine = 18
	assert.NotEqual(t, first, gitlabCQFingerprint(f2))
}
