package sources

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

// collectFragments drains a source into a slice so assertions can be made
// against the whole result.
func collectFragments(t *testing.T, s Source) []Fragment {
	t.Helper()

	var fragments []Fragment
	err := s.Fragments(context.Background(), func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)

	return fragments
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func TestFileFullPath(t *testing.T) {
	t.Run("without outer paths the path is returned as is", func(t *testing.T) {
		f := &File{Path: "some/file.txt"}
		require.Equal(t, "some/file.txt", f.FullPath())
	})

	t.Run("outer paths are joined with the separator", func(t *testing.T) {
		f := &File{Path: "inner.txt", outerPaths: []string{"outer.zip"}}
		require.Equal(t, "outer.zip"+InnerPathSeparator+"inner.txt", f.FullPath())
	})

	t.Run("nested outer paths keep their order", func(t *testing.T) {
		f := &File{Path: "inner.txt", outerPaths: []string{"outer.zip", "middle.tar"}}
		require.Equal(t,
			strings.Join([]string{"outer.zip", "middle.tar", "inner.txt"}, InnerPathSeparator),
			f.FullPath(),
		)
	})
}

func TestFileFragments(t *testing.T) {
	content := "first line\nsecond line\nthird line\n"
	path := writeTempFile(t, "example.txt", content)

	handle, err := os.Open(path)
	require.NoError(t, err)
	defer handle.Close()

	fragments := collectFragments(t, &File{Content: handle, Path: path})

	require.Len(t, fragments, 1)
	require.Equal(t, content, fragments[0].Raw)
	require.Equal(t, path, fragments[0].FilePath)
	// line numbers are one based
	require.Equal(t, 1, fragments[0].StartLine)
	require.Empty(t, fragments[0].SymlinkFile)
}

func TestFileFragmentsSymlink(t *testing.T) {
	path := writeTempFile(t, "example.txt", "content\n")

	handle, err := os.Open(path)
	require.NoError(t, err)
	defer handle.Close()

	fragments := collectFragments(t, &File{
		Content: handle,
		Path:    path,
		Symlink: "link.txt",
	})

	require.Len(t, fragments, 1)
	require.Equal(t, "link.txt", fragments[0].SymlinkFile)
}

func TestFileFragmentsEmptyFile(t *testing.T) {
	path := writeTempFile(t, "empty.txt", "")

	handle, err := os.Open(path)
	require.NoError(t, err)
	defer handle.Close()

	fragments := collectFragments(t, &File{Content: handle, Path: path})

	require.Empty(t, fragments, "an empty file should yield no fragments")
}

func TestFileFragmentsSkipsBinary(t *testing.T) {
	// a PDF header is enough for the type sniffer to classify the content as
	// an application type, which is skipped
	path := writeTempFile(t, "example.pdf", "%PDF-1.4\nbinary content here\n")

	handle, err := os.Open(path)
	require.NoError(t, err)
	defer handle.Close()

	fragments := collectFragments(t, &File{Content: handle, Path: path})

	require.Empty(t, fragments, "a binary file should yield no fragments")
}

func TestFileFragmentsCancelledContext(t *testing.T) {
	path := writeTempFile(t, "example.txt", "content\n")

	handle, err := os.Open(path)
	require.NoError(t, err)
	defer handle.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := &File{Content: handle, Path: path}
	err = f.Fragments(ctx, func(Fragment, error) error { return nil })

	require.ErrorIs(t, err, context.Canceled)
}

func Test_shouldSkipPath(t *testing.T) {
	t.Run("a nil config never skips", func(t *testing.T) {
		require.False(t, shouldSkipPath(nil, "any/path.txt"))
	})

	t.Run("a config without allowlists never skips", func(t *testing.T) {
		require.False(t, shouldSkipPath(&config.Config{}, "any/path.txt"))
	})

	cfg := &config.Config{
		Allowlists: []*config.Allowlist{
			{Paths: []*regexp.Regexp{regexp.MustCompile(`\.md$`)}},
			{Paths: []*regexp.Regexp{regexp.MustCompile(`^vendor/`)}},
		},
	}

	t.Run("a path matching an allowlist is skipped", func(t *testing.T) {
		require.True(t, shouldSkipPath(cfg, "README.md"))
	})

	t.Run("any allowlist may match", func(t *testing.T) {
		require.True(t, shouldSkipPath(cfg, "vendor/lib.go"))
	})

	t.Run("a path matching no allowlist is not skipped", func(t *testing.T) {
		require.False(t, shouldSkipPath(cfg, "main.go"))
	})

	t.Run("an empty path is not skipped", func(t *testing.T) {
		require.False(t, shouldSkipPath(cfg, ""))
	})
}
