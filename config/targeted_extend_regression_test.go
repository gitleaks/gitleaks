package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestExtendedTargetedAllowlists(t *testing.T) {
	for _, tc := range []struct {
		name      string
		outer     string
		wantCount int
	}{
		{name: "inherited", wantCount: 1},
		{name: "combine", outer: "\n[[allowlists]]\ntargetRules = [\"demo\"]\nregexes = ['second']\n", wantCount: 2},
		{name: "disabled", outer: "disabledRules = [\"demo\"]\n", wantCount: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extendDepth = 0
			viper.Reset()
			defer func() { extendDepth = 0; viper.Reset() }()
			dir := t.TempDir()
			base := filepath.Join(dir, "base.toml")
			require.NoError(t, os.WriteFile(base, []byte("[[rules]]\nid = 'demo'\nregex = 'TEST-[a-z]+'\n[[allowlists]]\ntargetRules = ['demo']\nregexes = ['first']\n"), 0600))
			outer := filepath.Join(dir, "outer.toml")
			content := fmt.Sprintf("[extend]\npath = %q\n%s", base, tc.outer)
			require.NoError(t, os.WriteFile(outer, []byte(content), 0600))
			viper.SetConfigFile(outer)
			require.NoError(t, viper.ReadInConfig())
			var vc ViperConfig
			require.NoError(t, viper.Unmarshal(&vc))
			cfg, err := vc.Translate()
			require.NoError(t, err)
			if tc.wantCount == -1 {
				_, ok := cfg.Rules["demo"]
				require.False(t, ok)
			} else {
				require.Len(t, cfg.Rules["demo"].Allowlists, tc.wantCount)
			}
		})
	}
}

func TestExtendedTargetedAllowlistAcrossTwoLevels(t *testing.T) {
	extendDepth = 0
	viper.Reset()
	defer func() { extendDepth = 0; viper.Reset() }()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.toml")
	middle := filepath.Join(dir, "middle.toml")
	outer := filepath.Join(dir, "outer.toml")
	require.NoError(t, os.WriteFile(base, []byte("[[rules]]\nid = 'demo'\nregex = 'TEST-[a-z]+'\n[[allowlists]]\ntargetRules = ['demo']\nregexes = ['first']\n"), 0600))
	require.NoError(t, os.WriteFile(middle, []byte(fmt.Sprintf("[extend]\npath = %q\n", base)), 0600))
	require.NoError(t, os.WriteFile(outer, []byte(fmt.Sprintf("[extend]\npath = %q\n", middle)), 0600))
	viper.SetConfigFile(outer)
	require.NoError(t, viper.ReadInConfig())
	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	require.Len(t, cfg.Rules["demo"].Allowlists, 1)
}

func TestExtendedTargetedAllowlistWithMissingRule(t *testing.T) {
	extendDepth = 0
	viper.Reset()
	defer func() { extendDepth = 0; viper.Reset() }()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.toml")
	outer := filepath.Join(dir, "outer.toml")
	require.NoError(t, os.WriteFile(base, []byte("[[allowlists]]\ntargetRules = ['missing']\nregexes = ['first']\n"), 0600))
	require.NoError(t, os.WriteFile(outer, []byte(fmt.Sprintf("[extend]\npath = %q\n", base)), 0600))
	viper.SetConfigFile(outer)
	require.NoError(t, viper.ReadInConfig())
	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	_, err := vc.Translate()
	require.ErrorContains(t, err, "target rule ID 'missing' does not exist")
}

func TestExtendedTargetedAllowlistForOuterRule(t *testing.T) {
	extendDepth = 0
	viper.Reset()
	defer func() { extendDepth = 0; viper.Reset() }()
	dir := t.TempDir()
	base := filepath.Join(dir, "base.toml")
	outer := filepath.Join(dir, "outer.toml")
	require.NoError(t, os.WriteFile(base, []byte("[[allowlists]]\ntargetRules = ['demo']\nregexes = ['first']\n"), 0600))
	content := fmt.Sprintf("[extend]\npath = %q\n[[rules]]\nid = 'demo'\nregex = 'TEST-[a-z]+'\n", base)
	require.NoError(t, os.WriteFile(outer, []byte(content), 0600))
	viper.SetConfigFile(outer)
	require.NoError(t, viper.ReadInConfig())
	var vc ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	require.Len(t, cfg.Rules["demo"].Allowlists, 1)
}
