package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// allowlistConfig builds a config with the subset of the default global
// allowlist paths relevant to directory skipping.
func allowlistConfig(t *testing.T) *config.Config {
	t.Helper()

	allowlist := &config.Allowlist{
		Paths: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$`),
			regexp.MustCompile(`(?:^|/)node_modules(?:/.*)?$`),
			regexp.MustCompile(`(?:^|/)\.git/`),
		},
	}
	require.NoError(t, allowlist.Validate())
	return &config.Config{Allowlists: []*config.Allowlist{allowlist}}
}

func TestShouldSkipDir(t *testing.T) {
	cfg := allowlistConfig(t)

	// A directory whose name looks like a file extension must NOT be
	// skipped. See https://github.com/gitleaks/gitleaks/issues/1821.
	require.False(t, shouldSkipDir(cfg, "goyaml.v2"))
	require.False(t, shouldSkipDir(cfg, filepath.Join("some", "path", "goyaml.v2")))
	require.False(t, shouldSkipDir(cfg, "foo.v2"))

	// ... but a file with such an extension still is.
	require.True(t, shouldSkipPath(cfg, "goyaml.v2"))
	require.True(t, shouldSkipPath(cfg, filepath.Join("some", "path", "foo.v2")))

	// Directories that are meant to be skipped still are.
	require.True(t, shouldSkipDir(cfg, "node_modules"))
	require.True(t, shouldSkipDir(cfg, filepath.Join("some", "path", "node_modules")))
	require.True(t, shouldSkipDir(cfg, ".git"))
	require.True(t, shouldSkipDir(cfg, filepath.Join("some", "path", ".git")))

	// ... and their contents are still skipped file-by-file.
	require.True(t, shouldSkipPath(cfg, filepath.Join(".git", "config")))
	require.True(t, shouldSkipPath(cfg, filepath.Join("node_modules", "pkg", "index.js")))
}

func TestScanTargets_DirectoryAllowlist(t *testing.T) {
	dir := t.TempDir()

	// A directory named like a file extension must still be walked.
	// See https://github.com/gitleaks/gitleaks/issues/1821.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "goyaml.v2"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "goyaml.v2", "secret.txt"), []byte("secret"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("secret"), 0o600))

	// Directories matched by the allowlist are still pruned.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("secret"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("secret"), 0o600))

	// A file with an allowlisted extension is still skipped.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "archive.v2"), []byte("secret"), 0o600))

	files := Files{Path: dir, Config: allowlistConfig(t)}

	var targets []string
	err := files.scanTargets(context.Background(), func(scanTarget ScanTarget, err error) error {
		require.NoError(t, err)
		rel, err := filepath.Rel(dir, scanTarget.Path)
		require.NoError(t, err)
		targets = append(targets, rel)
		return nil
	})
	require.NoError(t, err)

	require.ElementsMatch(t,
		[]string{
			filepath.Join("goyaml.v2", "secret.txt"),
			"plain.txt",
		},
		targets,
	)
}
