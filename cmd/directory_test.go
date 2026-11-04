package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression test for #1979: `gitleaks dir detect <file>` silently ignored the
// given path and scanned the entire current directory. Extra arguments and
// non-existent paths must be rejected instead of scanning the wrong target.
func TestResolveDirSource(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("VAULT_TOKEN=hvs.Va1234567123asdqwasd"), 0o600))

	tests := []struct {
		name     string
		args     []string
		expected string
		wantErr  bool
	}{
		{
			name:     "no args defaults to current dir",
			args:     nil,
			expected: ".",
		},
		{
			name:     "empty arg defaults to current dir",
			args:     []string{""},
			expected: ".",
		},
		{
			name:     "single file arg is used as-is",
			args:     []string{secretFile},
			expected: secretFile,
		},
		{
			name:     "single dir arg is used as-is",
			args:     []string{tmpDir},
			expected: tmpDir,
		},
		{
			name:    "legacy detect subcommand with file is rejected",
			args:    []string{"detect", "secret.txt"},
			wantErr: true,
		},
		{
			name:    "multiple paths are rejected",
			args:    []string{"secret.txt", "clean.txt"},
			wantErr: true,
		},
		{
			name:    "non-existent path is rejected",
			args:    []string{"detect"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := resolveDirSource(tt.args)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, source)
		})
	}
}

// The `dir` command must reject extra positional arguments at the CLI level,
// e.g. `gitleaks dir detect secret.txt`, instead of silently falling back to
// scanning the current directory. See #1979.
func TestDirectoryCmdRejectsExtraArgs(t *testing.T) {
	require.Error(t, directoryCmd.Args(directoryCmd, []string{"detect", "secret.txt"}))
	require.NoError(t, directoryCmd.Args(directoryCmd, []string{"secret.txt"}))
	require.NoError(t, directoryCmd.Args(directoryCmd, nil))
}
