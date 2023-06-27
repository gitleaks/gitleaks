package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/gitleaks/gitleaks/v8/config"
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
		tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
		if err != nil {
			t.Error(err)
		}
		viper.Reset()
		viper.AddConfigPath(configPath)
		viper.SetConfigName(test.cfgName)
		viper.SetConfigType("toml")
		err = viper.ReadInConfig()
		if err != nil {
			t.Error(err)
		}

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		if err != nil {
			t.Error(err)
		}

		cfg, err := vc.Translate()
		if err != nil {
			t.Error(err)
		}
		err = writeSarif(cfg, test.findings, tmpfile)
		fmt.Println(cfg)
		if err != nil {
			t.Error(err)
		}
		got, err := os.ReadFile(tmpfile.Name())
		if err != nil {
			t.Error(err)
		}
		if test.wantEmpty {
			if len(got) > 0 {
				t.Errorf("Expected empty file, got %s", got)
			}
			continue
		}
		want, err := os.ReadFile(test.expected)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(got, want) {
			err = os.WriteFile(strings.Replace(test.expected, ".sarif", ".got.sarif", 1), got, 0644)
			if err != nil {
				t.Error(err)
			}
			t.Errorf("got %s, want %s", string(got), string(want))
		}

	}
}
