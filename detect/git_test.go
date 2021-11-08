package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/git"
	"github.com/zricethezav/gitleaks/v8/report"
)

const repoBasePath = "../testdata/repos/"
const expectPath = "../testdata/expected/"
const configPath = "../testdata/config/"

// TestFromGit tests the FromGit function
func TestFromGit(t *testing.T) {
	tests := []struct {
		cfgName          string
		opts             Options
		source           string
		logOpts          string
		expected         string
		expectedFindings []*report.Finding
	}{
		{
			source:   filepath.Join(repoBasePath, "small"),
			expected: filepath.Join(expectPath, "git", "small.txt"),
			cfgName:  "simple",
			expectedFindings: []*report.Finding{
				{
					StartLine:   20,
					EndLine:     20,
					StartColumn: 19,
					EndColumn:   38,
					Content:     "AKIALALEMEL33243OLIA",
					File:        "main.go",
					// Line:        "\tawsToken := \"AKIALALEMEL33243OLIA\"",
					Commit:  "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587",
					Author:  "Zachary Rice",
					Email:   "zricer@protonmail.com",
					Date:    "2021-11-02 18:37:53 -0500 CDT",
					Message: "Accidentally add a secret",
					RuleID:  "aws-access-key",
				},
				{
					StartLine:   9,
					EndLine:     9,
					StartColumn: 17,
					EndColumn:   36,
					Content:     "AKIALALEMEL33243OLIA",
					File:        "foo/foo.go",
					// Line:        "\taws_token := \"AKIALALEMEL33243OLIA\"",
					Commit:  "491504d5a31946ce75e22554cc34203d8e5ff3ca",
					Author:  "Zach Rice",
					Email:   "zricer@protonmail.com",
					Date:    "2021-11-02 18:48:06 -0500 CDT",
					Message: "adding foo package with secret",
					RuleID:  "aws-access-key",
				},
			},
		},
		{
			source:   filepath.Join(repoBasePath, "small"),
			expected: filepath.Join(expectPath, "git", "small-branch-foo.txt"),
			logOpts:  "--all foo...",
			cfgName:  "simple",
			expectedFindings: []*report.Finding{
				{
					StartLine:   9,
					EndLine:     9,
					StartColumn: 17,
					EndColumn:   36,
					Content:     "AKIALALEMEL33243OLIA",
					// Line:        "\taws_token := \"AKIALALEMEL33243OLIA\"",
					File:    "foo/foo.go",
					Commit:  "491504d5a31946ce75e22554cc34203d8e5ff3ca",
					Author:  "Zach Rice",
					Email:   "zricer@protonmail.com",
					Date:    "2021-11-02 18:48:06 -0500 CDT",
					Message: "adding foo package with secret",
					RuleID:  "aws-access-key",
				},
			},
		},
	}

	err := moveDotGit("dotGit", ".git")
	if err != nil {
		t.Fatal(err)
	}
	defer moveDotGit(".git", "dotGit")

	for _, tt := range tests {
		files, err := git.GitLog(tt.source, tt.logOpts)
		if err != nil {
			t.Error(err)
		}

		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
		viper.SetConfigType("toml")
		err = viper.ReadInConfig()
		if err != nil {
			t.Error(err)
		}

		var vc config.ViperConfig
		viper.Unmarshal(&vc)
		cfg := vc.Translate()

		findings := FromGit(files, cfg, tt.opts)
		for _, f := range findings {
			f.Line = "" // remove lines cause copying and pasting them has some wack formatting
		}
		assert.ElementsMatch(t, tt.expectedFindings, findings)
	}
}

func moveDotGit(from, to string) error {
	repoDirs, err := os.ReadDir("../testdata/repos")
	if err != nil {
		return err
	}
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
		if err != nil {
			return err
		}
	}
	return nil
}
