package config_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
)

const configPath = "../testdata/configs/"

func TestParse(t *testing.T) {
	tests := []struct {
		description   string
		opts          options.Options
		wantErr       error
		wantFileRegex *regexp.Regexp
		wantMessages  *regexp.Regexp
		wantAllowlist config.AllowList
	}{
		{
			description: "default config",
			opts:        options.Options{},
		},
		{
			description: "test successful load",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "aws_key.toml"),
			},
		},
		{
			description: "test bad toml",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_aws_key.toml"),
			},
			wantErr: fmt.Errorf("Near line 7 (last key parsed 'rules.description'): expected value but found \"AWS\" instead"),
		},
		{
			description: "test bad regex",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_regex_aws_key.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: invalid nested repetition operator: `???`"),
		},
		{
			description: "test bad global allowlist file regex",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_aws_key_global_allowlist_file.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: missing argument to repetition operator: `??`"),
		},
		{
			description: "test bad global file regex",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_aws_key_file_regex.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: error parsing regexp: missing argument to repetition operator: `??`"),
		},
		{
			description: "test successful load big ol thing",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "large.toml"),
			},
		},
		{
			description: "test load entropy",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "entropy.toml"),
			},
		},
		{
			description: "test entropy bad range",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_1.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: entropy Min value cannot be higher than Max value"),
		},
		{
			description: "test entropy value max",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_2.toml"),
			},
			wantErr: fmt.Errorf("strconv.ParseFloat: parsing \"x\": invalid syntax"),
		},
		{
			description: "test entropy value min",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_3.toml"),
			},
			wantErr: fmt.Errorf("strconv.ParseFloat: parsing \"x\": invalid syntax"),
		},
		{
			description: "test entropy value group",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_4.toml"),
			},
			wantErr: fmt.Errorf("strconv.ParseInt: parsing \"x\": invalid syntax"),
		},
		{
			description: "test entropy value group",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_5.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: group cannot be lower than 0"),
		},
		{
			description: "test entropy value group",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_6.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: group cannot be higher than number of groups in regexp"),
		},
		{
			description: "test entropy range limits",
			opts: options.Options{
				ConfigPath: filepath.Join(configPath, "bad_entropy_7.toml"),
			},
			wantErr: fmt.Errorf("problem loading config: invalid entropy ranges, must be within 0.0-8.0"),
		},
	}

	for _, test := range tests {
		_, err := config.NewConfig(test.opts)
		if err != nil {
			if test.wantErr == nil {
				t.Error(test.description, err)
			} else if test.wantErr.Error() != err.Error() {
				t.Errorf("expected err: %s, got %s", test.wantErr, err)
			}
		}
	}
}

// TestParseFields will test that fields are properly parsed from a config. As fields are added, then please
// add tests here.
func TestParseFields(t *testing.T) {
	tomlConfig := `
[[rules]]
	description = "Some Groups without a reportGroup"
	regex = '(.)(.)'

[[rules]]
	description = "Some Groups"
	regex = '(.)(.)'
  reportGroup = 1
`
	configPath, err := writeTestConfig(tomlConfig)
	defer os.Remove(configPath)
	if err != nil {
		t.Fatal(err)
	}

	config, err := config.NewConfig(options.Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("Couldn't parse config: %v", err)
	}

	expectedRuleFields := []struct {
		Description string
		ReportGroup int
	}{
		{
			Description: "Some Groups without a reportGroup",
			ReportGroup: 0,
		},
		{
			Description: "Some Groups",
			ReportGroup: 1,
		},
	}

	if len(config.Rules) != len(expectedRuleFields) {
		t.Fatalf("expected %v rules", len(expectedRuleFields))
	}

	for _, expected := range expectedRuleFields {
		rule, err := findRuleByDescription(config.Rules, expected.Description)
		if err != nil {
			t.Fatal(err)
		}
		if rule.ReportGroup != expected.ReportGroup {
			t.Errorf("expected the rule with description '%v' to have a ReportGroup of %v", expected.Description, expected.ReportGroup)
		}
	}
}

func findRuleByDescription(rules []config.Rule, description string) (*config.Rule, error) {
	for _, rule := range rules {
		if rule.Description == description {
			return &rule, nil
		}
	}

	return nil, fmt.Errorf("Couldn't find rule with the description: %s", description)
}

func writeTestConfig(toml string) (string, error) {
	tmpfile, err := ioutil.TempFile("", "testConfig")
	if err != nil {
		return "", fmt.Errorf("Couldn't create test config got: %w", err)
	}

	if _, err := tmpfile.Write([]byte(toml)); err != nil {
		return "", fmt.Errorf("Couldn't create test config got: %w", err)
	}

	if err := tmpfile.Close(); err != nil {
		return "", fmt.Errorf("Couldn't create test config got: %w", err)
	}

	return tmpfile.Name(), nil
}

func TestAppendingConfiguration(t *testing.T) {
	testRegexA, _ := regexp.Compile("a")
	testRegexB, _ := regexp.Compile("b")

	allowListA := config.AllowList{
		Description: "Test Description",
		Commits:     []string{"a"},
		Files:       []*regexp.Regexp{testRegexA},
		Paths:       []*regexp.Regexp{testRegexA},
		Regexes:     []*regexp.Regexp{testRegexA},
		Repos:       []*regexp.Regexp{testRegexA},
	}

	allowListB := config.AllowList{
		Description: "Test Description",
		Commits:     []string{"b"},
		Files:       []*regexp.Regexp{testRegexB},
		Paths:       []*regexp.Regexp{testRegexB},
		Regexes:     []*regexp.Regexp{testRegexB},
		Repos:       []*regexp.Regexp{testRegexB},
	}

	ruleA := config.Rule{Description: "a"}
	ruleB := config.Rule{Description: "b"}

	rulesA := []config.Rule{ruleA}
	rulesB := []config.Rule{ruleB}

	cfgA := config.Config{
		Rules:     rulesA,
		Allowlist: allowListA,
	}

	cfgB := config.Config{
		Rules:     rulesB,
		Allowlist: allowListB,
	}

	cfgAppended := cfgA.AppendConfig(cfgB)

	if !(len(cfgAppended.Rules) == 2) {
		t.Errorf("Length of Appended Rules = %d; want 2", len(cfgAppended.Rules))
	}

	if !(len(cfgAppended.Allowlist.Commits) == 2) {
		t.Errorf("Length of Appended Allowed Commits = %d; want 2", len(cfgAppended.Allowlist.Commits))
	}

	if !(len(cfgAppended.Allowlist.Files) == 2) {
		t.Errorf("Length of Appended Allowed Files = %d; want 2", len(cfgAppended.Allowlist.Files))
	}

	if !(len(cfgAppended.Allowlist.Paths) == 2) {
		t.Errorf("Length of Appended Allowed Paths = %d; want 2", len(cfgAppended.Allowlist.Paths))
	}

	if !(len(cfgAppended.Allowlist.Regexes) == 2) {
		t.Errorf("Length of Appended Allowed Regexes = %d; want 2", len(cfgAppended.Allowlist.Regexes))
	}

	if !(len(cfgAppended.Allowlist.Repos) == 2) {
		t.Errorf("Length of Appended Allowed Repos = %d; want 2", len(cfgAppended.Allowlist.Repos))
	}

	if cfgAppended.Allowlist.Description != "Appended Configuration" {
		t.Errorf("Allow List Description is = \"%s\"; want \"Appended Configuration\"", cfgAppended.Allowlist.Description)
	}

}
