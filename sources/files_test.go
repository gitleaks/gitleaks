package sources

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
)

func TestFiles_DisplayPath(t *testing.T) {
	tmp := t.TempDir()
	nested := filepath.Join(tmp, "nested")
	require.NoError(t, os.MkdirAll(nested, 0o755))

	innerFile := filepath.Join(nested, "secret.env")
	require.NoError(t, os.WriteFile(innerFile, []byte("x"), 0o644))

	rootFile := filepath.Join(tmp, "top.env")
	require.NoError(t, os.WriteFile(rootFile, []byte("x"), 0o644))

	cases := []struct {
		name           string
		source         string
		target         string
		relativePaths  bool
		expected       string
	}{
		{
			name:          "absolute when flag off",
			source:        tmp,
			target:        innerFile,
			relativePaths: false,
			expected:      innerFile,
		},
		{
			name:          "directory source strips prefix",
			source:        tmp,
			target:        innerFile,
			relativePaths: true,
			expected:      filepath.Join("nested", "secret.env"),
		},
		{
			name:          "file source collapses to basename",
			source:        rootFile,
			target:        rootFile,
			relativePaths: true,
			expected:      "top.env",
		},
		{
			name:          "directory source with file at root",
			source:        tmp,
			target:        rootFile,
			relativePaths: true,
			expected:      "top.env",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &Files{Path: c.source, SourceRelativePaths: c.relativePaths}
			require.Equal(t, c.expected, f.displayPath(c.target))
		})
	}
}

func TestFiles_FragmentsSourceRelativePaths(t *testing.T) {
	tmp := t.TempDir()
	nested := filepath.Join(tmp, "sub")
	require.NoError(t, os.MkdirAll(nested, 0o755))

	wantRel := filepath.Join("sub", "leak.txt")
	require.NoError(t, os.WriteFile(filepath.Join(nested, "leak.txt"), []byte("hello\n"), 0o644))

	collect := func(s *Files) []string {
		var (
			mu    sync.Mutex
			paths []string
		)
		s.Sema = semgroup.NewGroup(context.Background(), 1)
		err := s.Fragments(context.Background(), func(fr Fragment, err error) error {
			if err != nil {
				return err
			}
			mu.Lock()
			paths = append(paths, fr.FilePath)
			mu.Unlock()
			return nil
		})
		require.NoError(t, err)
		require.NoError(t, s.Sema.Wait())
		sort.Strings(paths)
		return paths
	}

	t.Run("flag off keeps absolute paths", func(t *testing.T) {
		got := collect(&Files{Path: tmp})
		require.Equal(t, []string{filepath.Join(tmp, wantRel)}, got)
	})

	t.Run("flag on yields source-relative paths", func(t *testing.T) {
		got := collect(&Files{Path: tmp, SourceRelativePaths: true})
		require.Equal(t, []string{wantRel}, got)
	})
}
