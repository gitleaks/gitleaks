package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
)

// A file that cannot be opened must surface as an error so the caller reports
// a partial scan, instead of being silently skipped while the run claims
// "no leaks found" with exit code 0.
func TestFragments_UnopenableFileReturnsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for root")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing secret here"), 0o644))
	blocked := filepath.Join(dir, "blocked.txt")
	require.NoError(t, os.WriteFile(blocked, []byte("nothing secret here"), 0o644))
	require.NoError(t, os.Chmod(blocked, 0o000))

	s := &Files{
		Config: &config.Config{},
		Path:   dir,
		Sema:   semgroup.NewGroup(context.Background(), 4),
	}

	err := s.Fragments(context.Background(), func(fragment Fragment, err error) error {
		return err
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked.txt")
}
