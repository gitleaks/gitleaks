package detect

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestDetectFindings(t *testing.T) {
	tests := []struct {
		cfgName          string
		opts             Options
		filePath         string
		bytes            []byte
		commit           string
		expectedFindings []report.Finding
	}{
		{
			cfgName:  "simple",
			bytes:    []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath: "tmp.go",
			expectedFindings: []report.Finding{
				{
					Content: "AKIALALEMEL33243OLIA",
					File:    "tmp.go",
					RuleID:  "aws-access-key",
				},
			},
		},
		{
			cfgName:          "allow_aws_re",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:          "allow_path",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
		},
		{
			cfgName:          "allow_commit",
			bytes:            []byte(`awsToken := \"AKIALALEMEL33243OLIA\"`),
			filePath:         "tmp.go",
			expectedFindings: []report.Finding{},
			commit:           "allowthiscommit",
		},
	}

	for _, tt := range tests {
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(tt.cfgName)
		viper.SetConfigType("toml")
		err := viper.ReadInConfig()
		if err != nil {
			t.Error(err)
		}

		var vc config.ViperConfig
		viper.Unmarshal(&vc)
		cfg := vc.Translate()

		findings := DetectFindings(cfg, tt.bytes, tt.filePath, tt.commit)
		for _, f := range findings {
			f.Line = "" // remove lines cause copying and pasting them has some wack formatting
			f.Date = ""
		}

		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}
