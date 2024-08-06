package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		cfgName          string
		fragment         Fragment
		findings         []report.Finding
		expectedFindings []report.Finding
		wantError        error
	}{
		{
			cfgName: "validate",
			fragment: Fragment{
				Raw:      `dont matter`,
				FilePath: "tmp.go",
			},
			findings: []report.Finding{
				{
					Match:  os.Getenv("GITHUB_TOKEN"),
					Secret: os.Getenv("GITHUB_TOKEN"),
					Commit: "1234567890abcdefghijjj",
					RuleID: "github-pat",
				},
				{
					Match:  "ghp_1234567890abcdefghzzzz",
					Secret: "ghp_1234567890abcdefghzzzz",
					Commit: "1234567890abcdefghijjj",
					RuleID: "github-pat",
				},
			},
			expectedFindings: []report.Finding{
				{
					Match:  "ghp_1234567890abcdefghijjj",
					Secret: "ghp_1234567890abcdefghijjj",
					Commit: "1234567890abcdefghijjj",
					RuleID: "github-pat",
				},
			},
		},
		// {
		// 	cfgName: "validate",
		// 	fragment: Fragment{
		// 		Raw:      `dont matter`,
		// 		FilePath: "tmp.go",
		// 	},
		// 	findings: []report.Finding{
		// 		{
		// 			Match:  "adobbe-id-1",
		// 			Secret: "adobbe-id-1",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-id",
		// 		},
		// 		{
		// 			Match:  "adobbe-id-2",
		// 			Secret: "adobbe-id-2",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-id",
		// 		},
		// 		{
		// 			Match:  "adobbe-key-1",
		// 			Secret: "adobbe-key-1",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-project-key",
		// 		},
		// 		{
		// 			Match:  "adobbe-key-2",
		// 			Secret: "adobbe-key-2",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "adobe-project-key",
		// 		},
		// 	},
		// 	expectedFindings: []report.Finding{
		// 		{
		// 			Match:  "ghp_1234567890abcdefghijjj",
		// 			Secret: "ghp_1234567890abcdefghijjj",
		// 			Commit: "1234567890abcdefghijjj",
		// 			RuleID: "github-pat",
		// 		},
		// 	},
		// },
	}

	for _, tt := range tests {
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

		d.Verify(tt.findings)
		// assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
