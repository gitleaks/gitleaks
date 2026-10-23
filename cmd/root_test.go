package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A report file catalogs every secret a scan found, so it must never be
// readable by other local users, regardless of the process umask.
func Test_openReportFile_RestrictivePermissions(t *testing.T) {
	t.Run("new file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report.json")

		f, err := openReportFile(path)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Zero(t, info.Mode().Perm()&0o077,
			"report file must not be group/world readable, got %o", info.Mode().Perm())
	})

	t.Run("pre-existing file with permissive mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report.json")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

		f, err := openReportFile(path)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Zero(t, info.Mode().Perm()&0o077,
			"pre-existing report file must be locked down, got %o", info.Mode().Perm())
		require.Zero(t, info.Size(), "report file must be truncated")
	})
}
