package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

const configPath = "../testdata/config/"
const repoBasePath = "../testdata/repos/"

func TestDetect(t *testing.T) {
	tests := []struct {
		cfgName  string
		fragment Fragment
		// NOTE: for expected findings, all line numbers will be 0
		// because line deltas are added _after_ the finding is created.
		// I.e, if the finding is from a --no-git file, the line number will be
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
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw: `awsToken := \

		        \"AKIALALEMEL33243OKIA\ // gitleaks:allow"

		        `,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
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
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_path",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_commit",
			fragment: Fragment{
				Raw:       `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath:  "tmp.go",
				CommitSHA: "allowthiscommit",
			},
			expectedFindings: []report.Finding{},
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
			expectedFindings: []report.Finding{},
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
			expectedFindings: []report.Finding{},
			wantError:        fmt.Errorf("Discord API key invalid regex secret group 5, max regex secret group 3"),
		},
		{
			cfgName: "simple",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: filepath.Join(configPath, "simple.toml"),
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "allow_global_aws_re",
			fragment: Fragment{
				Raw:      `awsToken := \"AKIALALEMEL33243OLIA\"`,
				FilePath: "tmp.go",
			},
			expectedFindings: []report.Finding{},
		},
		{
			cfgName: "generic_with_py_path",
			fragment: Fragment{
				Raw:      `const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				FilePath: "tmp.py",
			},
			expectedFindings: []report.Finding{},
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
		err = viper.Unmarshal(&vc)
		if err != nil {
			t.Error(err)
		}
		cfg, err := vc.Translate()
		cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
		if tt.wantError != nil {
			if err == nil {
				t.Errorf("expected error")
			}
			assert.Equal(t, tt.wantError, err)
		}
		d := NewDetector(cfg)

		findings := d.Detect(tt.fragment)
		assert.ElementsMatch(t, tt.expectedFindings, findings)
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
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
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
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587:main.go:aws-access-key:20",
				},
				{
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
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "491504d5a31946ce75e22554cc34203d8e5ff3ca:foo/foo.go:aws-access-key:9",
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "small"),
			logOpts: "--all foo...",
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
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
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Entropy:     3.0841837,
					Fingerprint: "491504d5a31946ce75e22554cc34203d8e5ff3ca:foo/foo.go:aws-access-key:9",
				},
			},
		},
	}

	err := moveDotGit("dotGit", ".git")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := moveDotGit(".git", "dotGit"); err != nil {
			t.Error(err)
		}
	}()

	for _, tt := range tests {

		viper.AddConfigPath(configPath)
		viper.SetConfigName("simple")
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
		detector := NewDetector(cfg)
		findings, err := detector.DetectGit(tt.source, tt.logOpts, DetectType)
		if err != nil {
			t.Error(err)
		}

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
		err = viper.Unmarshal(&vc)
		if err != nil {
			t.Error(err)
		}
		cfg, _ := vc.Translate()
		detector := NewDetector(cfg)
		detector.FollowSymlinks = true
		findings, err := detector.DetectFiles(tt.source)
		if err != nil {
			t.Error(err)
		}

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
		if err != nil {
			t.Error(err)
		}

		var vc config.ViperConfig
		err = viper.Unmarshal(&vc)
		if err != nil {
			t.Error(err)
		}
		cfg, _ := vc.Translate()
		detector := NewDetector(cfg)
		detector.FollowSymlinks = true
		findings, err := detector.DetectFiles(tt.source)
		if err != nil {
			t.Error(err)
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
