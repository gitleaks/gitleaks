package sources

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

// buildTree writes the given name -> content pairs under a fresh temp dir and
// returns the root.
func buildTree(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}

	return root
}

// collectTargets walks the source and returns the discovered paths relative to
// root, so assertions do not depend on the temp dir name.
func collectTargets(t *testing.T, s *Files, root string) []string {
	t.Helper()

	var found []string
	err := s.scanTargets(context.Background(), func(target ScanTarget, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, target.Path)
		require.NoError(t, relErr)
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	require.NoError(t, err)

	sort.Strings(found)
	return found
}

func TestFilesScanTargets(t *testing.T) {
	root := buildTree(t, map[string]string{
		"a.txt":      "content a",
		"b.txt":      "content b",
		"sub/c.txt":  "content c",
		"sub/deep/d": "content d",
		"empty.txt":  "",
	})

	found := collectTargets(t, &Files{Path: root}, root)

	// the empty file is skipped, directories are never yielded
	require.Equal(t, []string{"a.txt", "b.txt", "sub/c.txt", "sub/deep/d"}, found)
}

func TestFilesScanTargetsSkipsEmptyFiles(t *testing.T) {
	root := buildTree(t, map[string]string{
		"empty.txt":    "",
		"nonempty.txt": "x",
	})

	found := collectTargets(t, &Files{Path: root}, root)

	require.Equal(t, []string{"nonempty.txt"}, found)
}

func TestFilesScanTargetsRespectsMaxFileSize(t *testing.T) {
	root := buildTree(t, map[string]string{
		"small.txt": "x",
		"large.txt": "this content is definitely longer than five bytes",
	})

	found := collectTargets(t, &Files{Path: root, MaxFileSize: 5}, root)

	require.Equal(t, []string{"small.txt"}, found)
}

func TestFilesScanTargetsSkipsAllowlistedFiles(t *testing.T) {
	root := buildTree(t, map[string]string{
		"keep.go":   "content",
		"README.md": "content",
	})

	files := &Files{
		Path: root,
		Config: &config.Config{
			Allowlists: []*config.Allowlist{
				{Paths: []*regexp.Regexp{regexp.MustCompile(`\.md$`)}},
			},
		},
	}

	require.Equal(t, []string{"keep.go"}, collectTargets(t, files, root))
}

func TestFilesScanTargetsSkipsAllowlistedDirectories(t *testing.T) {
	root := buildTree(t, map[string]string{
		"keep.go":         "content",
		"vendor/lib.go":   "content",
		"vendor/dep/x.go": "content",
	})

	files := &Files{
		Path: root,
		Config: &config.Config{
			Allowlists: []*config.Allowlist{
				{Paths: []*regexp.Regexp{regexp.MustCompile(`vendor$`)}},
			},
		},
	}

	// skipping a directory prunes everything beneath it
	require.Equal(t, []string{"keep.go"}, collectTargets(t, files, root))
}

func TestFilesScanTargetsEmptyDirectory(t *testing.T) {
	root := t.TempDir()

	require.Empty(t, collectTargets(t, &Files{Path: root}, root))
}
