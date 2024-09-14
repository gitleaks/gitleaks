package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

const configPath = "../testdata/config/"

func TestWriteSarif(t *testing.T) {
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
			expected:       filepath.Join(expectPath, "report", "sarif_simple.sarif"),
			findings: []Finding{
				{

					Description: "A test rule",
					RuleID:      "test-rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "opps",
					File:        "auth.py",
					Commit:      "0000000000000000",
					Author:      "John Doe",
					Email:       "johndoe@gmail.com",
					Date:        "10-19-2003",
					Tags:        []string{"tag1", "tag2", "tag3"},
				},
			}},
	}

	for _, test := range tests {
		t.Run(test.cfgName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
			require.NoError(t, err)
			viper.Reset()
			viper.AddConfigPath(configPath)
			viper.SetConfigName(test.cfgName)
			viper.SetConfigType("toml")
			err = viper.ReadInConfig()
			require.NoError(t, err)

			var vc config.ViperConfig
			err = viper.Unmarshal(&vc)
			require.NoError(t, err)

			cfg, err := vc.Translate()
			require.NoError(t, err)
			err = writeSarif(cfg, test.findings, tmpfile)
			require.NoError(t, err)
			assert.FileExists(t, tmpfile.Name())
			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)
			if test.wantEmpty {
				assert.Empty(t, got)
				return
			}
			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}
