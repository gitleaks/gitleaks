package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPreCommitHooksDoNotPassFilenames(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", ".pre-commit-hooks.yaml"))
	require.NoError(t, err)

	var hooks []struct {
		ID            string `yaml:"id"`
		PassFilenames *bool  `yaml:"pass_filenames"`
	}
	require.NoError(t, yaml.Unmarshal(data, &hooks))

	for _, id := range []string{"gitleaks", "gitleaks-docker", "gitleaks-system"} {
		t.Run(id, func(t *testing.T) {
			for _, hook := range hooks {
				if hook.ID != id {
					continue
				}
				// Pre-commit passes filenames by default, but the git subcommand scans
				// staged changes itself and accepts at most one repository argument.
				require.NotNil(t, hook.PassFilenames, "hook must explicitly disable filename arguments")
				require.False(t, *hook.PassFilenames)
				return
			}
			t.Fatalf("hook %q not found", id)
		})
	}
}
