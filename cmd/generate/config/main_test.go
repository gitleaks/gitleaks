package main

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestConfigTemplateIncludesRequiredRules(t *testing.T) {
	withinLines := 3
	withinColumns := 24
	cfg := config.Config{
		Title: "test config",
		Rules: map[string]config.Rule{
			"primary-rule": {
				RuleID:      "primary-rule",
				Description: "Primary rule",
				Regex:       regexp.MustCompile(`primary-([a-z]+)`),
				RequiredRules: []*config.Required{
					{
						RuleID:        "required-rule",
						WithinLines:   &withinLines,
						WithinColumns: &withinColumns,
					},
				},
			},
			"required-rule": {
				RuleID:      "required-rule",
				Description: "Required rule",
				Regex:       regexp.MustCompile(`required-([a-z]+)`),
			},
		},
	}

	output := renderConfigTemplate(t, cfg)
	assert.Contains(t, output, "[[rules.required]]")
	assert.Contains(t, output, `id = "required-rule"`)
	assert.Contains(t, output, "withinLines = 3")
	assert.Contains(t, output, "withinColumns = 24")

	v := viper.New()
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(output)))

	var vc config.ViperConfig
	require.NoError(t, v.Unmarshal(&vc))
	parsed, err := vc.Translate()
	require.NoError(t, err)

	primaryRule := parsed.Rules["primary-rule"]
	require.Len(t, primaryRule.RequiredRules, 1)
	require.NotNil(t, primaryRule.RequiredRules[0].WithinLines)
	require.NotNil(t, primaryRule.RequiredRules[0].WithinColumns)
	assert.Equal(t, "required-rule", primaryRule.RequiredRules[0].RuleID)
	assert.Equal(t, withinLines, *primaryRule.RequiredRules[0].WithinLines)
	assert.Equal(t, withinColumns, *primaryRule.RequiredRules[0].WithinColumns)
}

func renderConfigTemplate(t *testing.T, cfg config.Config) string {
	t.Helper()

	tmpl, err := template.ParseFiles(templatePath)
	require.NoError(t, err)

	var output bytes.Buffer
	require.NoError(t, tmpl.Execute(&output, cfg))
	return output.String()
}
