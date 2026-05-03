package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPyprojectPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"pyproject.toml", true},
		{"./pyproject.toml", true},
		{"/abs/path/pyproject.toml", true},
		{"PyProject.toml", true},
		{".gitleaks.toml", false},
		{"gitleaks.toml", false},
		{"/some/dir/", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, isPyprojectPath(tc.path))
		})
	}
}

func TestExtractGitleaksFromPyproject_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[project]
name = "myapp"
version = "1.2.3"

[tool.black]
line-length = 100

[tool.gitleaks]
title = "myapp gitleaks config"

[[tool.gitleaks.rules]]
id = "custom-token"
description = "Custom internal token"
regex = '''internal-[a-z0-9]{32}'''
keywords = ["internal-"]
`), 0o644))

	out, err := extractGitleaksFromPyproject(path)
	require.NoError(t, err)
	require.NotEmpty(t, out)

	// Feed it through viper the same way initConfig will at runtime.
	v := viper.New()
	v.SetConfigType("toml")
	require.NoError(t, v.ReadConfig(strings.NewReader(string(out))))

	assert.Equal(t, "myapp gitleaks config", v.GetString("title"))
	rules := v.Get("rules")
	require.NotNil(t, rules, "the [[tool.gitleaks.rules]] array of tables should land at top-level rules")
	rs, ok := rules.([]any)
	require.True(t, ok, "rules should decode as a TOML array of tables, got %T", rules)
	require.Len(t, rs, 1)
	first, ok := rs[0].(map[string]any)
	require.True(t, ok, "first rule should be a TOML table, got %T", rs[0])
	assert.Equal(t, "custom-token", first["id"])
}

func TestExtractGitleaksFromPyproject_NoTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[project]
name = "myapp"

[tool.black]
line-length = 100
`), 0o644))

	_, err := extractGitleaksFromPyproject(path)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errNoGitleaksTable))
}

func TestExtractGitleaksFromPyproject_NoToolKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(path, []byte(`
[project]
name = "myapp"
`), 0o644))

	_, err := extractGitleaksFromPyproject(path)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errNoGitleaksTable))
}

func TestExtractGitleaksFromPyproject_FileMissing(t *testing.T) {
	_, err := extractGitleaksFromPyproject(filepath.Join(t.TempDir(), "missing.toml"))
	require.Error(t, err)
}

func TestExtractGitleaksFromPyproject_InvalidToml(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	require.NoError(t, os.WriteFile(path, []byte("this is = not = valid [toml"), 0o644))

	_, err := extractGitleaksFromPyproject(path)
	require.Error(t, err)
}
