package detect

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// TestFromGit tests the FromGit function
func TestFromFiles(t *testing.T) {
	tests := []struct {
		cfgName          string
		opts             Options
		source           string
		expectedFindings []*report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "nogit"),
			cfgName: "simple",
			expectedFindings: []*report.Finding{
				{
					StartLine:   19,
					EndLine:     19,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Content:     "AKIALALEMEL33243OLIA",
					File:        "../testdata/repos/nogit/main.go",
					RuleID:      "aws-access-key",
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", "main.go"),
			cfgName: "simple",
			expectedFindings: []*report.Finding{
				{
					StartLine:   19,
					EndLine:     19,
					StartColumn: 16,
					EndColumn:   35,
					Line:        "\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Content:     "AKIALALEMEL33243OLIA",
					File:        "../testdata/repos/nogit/main.go",
					RuleID:      "aws-access-key",
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
		cfg := vc.Translate()

		findings, err := FromFiles(tt.source, cfg, tt.opts)
		if err != nil {
			t.Error(err)
		}

		if !findingsMatch(t, findings, tt.expectedFindings) {
			for _, f := range findings {
				t.Errorf("got:    %v", *f)
			}
			for _, f := range tt.expectedFindings {
				t.Errorf("want:   %v", *f)
			}
			t.Error("findings don't match")
			t.Error("got: ", findings)
			t.Error("want: ", tt.expectedFindings)
		}

		// assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func findingsMatch(t *testing.T, got []*report.Finding, want []*report.Finding) bool {
	if len(got) != len(want) {
		return false
	}
	m := make(map[string]bool)
	for _, f := range got {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%v", *f)))
		m[fmt.Sprintf("%x", h.Sum(nil))] = true
	}

	for _, f := range want {
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%v", *f)))
		if _, ok := m[fmt.Sprintf("%x", h.Sum(nil))]; !ok {
			return false
		}

	}
	return true
}
