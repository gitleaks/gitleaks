package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestRootRelativePath(t *testing.T) {
	cases := map[string]struct {
		root, path, expected string
	}{
		"no root": {
			root: "", path: "src/x.py", expected: "",
		},
		"relative root": {
			root: "repo", path: filepath.Join("repo", "src", "x.py"), expected: "src/x.py",
		},
		"dot root": {
			root: ".", path: filepath.Join("src", "x.py"), expected: "src/x.py",
		},
		"absolute root": {
			root:     filepath.Join(os.TempDir(), "repo"),
			path:     filepath.Join(os.TempDir(), "repo", "src", "x.py"),
			expected: "src/x.py",
		},
		"slash-separated path under an OS-separated root": {
			root: "repo", path: "repo/src/x.py", expected: "src/x.py",
		},
		"the root itself": {
			root: "repo", path: "repo", expected: "",
		},
		"outside the root": {
			root: filepath.Join("repo", "src"), path: filepath.Join("repo", "other", "x.py"), expected: "",
		},
		"archive member keeps its inner path": {
			root:     "repo",
			path:     "repo/bundle.tar!inner/x.py",
			expected: "bundle.tar!inner/x.py",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, RootRelativePath(tc.root, tc.path))
		})
	}
}

// An allowlist path is written against the scan root. It has to skip the
// same files whether the root is given as `.`, as a relative path from
// another directory, or as an absolute path.
func TestFilesAllowlistPathsMatchRelativeToRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "src", "vendor"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "src", "vendor", "lib.py"), []byte("x = 1\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "src", "app.py"), []byte("y = 2\n"), 0o644))

	cfg := &config.Config{
		Allowlists: []*config.Allowlist{{
			Paths: []*regexp.Regexp{regexp.MustCompile(`^src/vendor/`)},
		}},
	}
	for _, a := range cfg.Allowlists {
		require.NoError(t, a.Validate())
	}

	for name, source := range map[string]string{
		"absolute root": root,
		"relative root": relativeToCwd(t, root),
	} {
		t.Run(name, func(t *testing.T) {
			files := &Files{
				Config: cfg,
				Path:   source,
				Sema:   semgroup.NewGroup(context.Background(), 1),
			}
			var scanned []string
			err := files.scanTargets(context.Background(), func(target ScanTarget, err error) error {
				require.NoError(t, err)
				scanned = append(scanned, RootRelativePath(source, target.Path))
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, []string{"src/app.py"}, scanned)
		})
	}
}

// Fragments from a directory scan carry the root, and archive members carry
// it too, so the detector can match against root-relative paths.
func TestFilesFragmentsCarryTheRoot(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "src", "app.py"), []byte("y = 2\n"), 0o644))

	files := &Files{
		Path: root,
		Sema: semgroup.NewGroup(context.Background(), 1),
	}
	var fragments []Fragment
	err := files.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, fragments, 1)
	assert.Equal(t, root, fragments[0].Root)
	assert.Equal(t, "src/app.py", RootRelativePath(fragments[0].Root, fragments[0].FilePath))

	// A single file is not a directory scan; there is no root to be relative to.
	single := &Files{
		Path: filepath.Join(root, "src", "app.py"),
		Sema: semgroup.NewGroup(context.Background(), 1),
	}
	fragments = nil
	err = single.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, fragments, 1)
	assert.Empty(t, fragments[0].Root)
}

func relativeToCwd(t *testing.T, path string) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	rel, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Skipf("%s cannot be expressed relative to %s", path, cwd)
	}
	return rel
}
