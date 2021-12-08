package detect

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// TestFromGit tests the FromGit function
func TestFromFiles(t *testing.T) {
	tests := []struct {
		cfgName          string
		opts             Options
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "nogit"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   19,
					EndLine:     19,
					StartColumn: 16,
					EndColumn:   35,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/repos/nogit/main.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", "main.go"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					StartLine:   19,
					EndLine:     19,
					StartColumn: 16,
					EndColumn:   35,
					Match:       "AKIALALEMEL33243OLIA",
					Secret:      "AKIALALEMEL33243OLIA",
					File:        "../testdata/repos/nogit/main.go",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
				},
			},
		},
	}

	for _, tt := range tests {
		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil {
			t.Error(err)
		}

		var vc config.ViperConfig
		viper.Unmarshal(&vc)
		cfg, _ := vc.Translate()

		findings, err := FromFiles(tt.source, cfg, tt.opts)
		if err != nil {
			t.Error(err)
		}

		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
