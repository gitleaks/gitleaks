package detect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// A directory scan reports paths the way the root was spelled, so
// `gitleaks dir .` and `gitleaks dir /abs/path` print different fingerprints
// for the same file. Everything that matches a path against the report —
// .gitleaksignore, allowlist paths, and the config/baseline self-skip — has to
// give the same answer for both spellings, the way a git scan does with
// repository-relative paths.

const dirRootSecret = "AKIALALEMEL33243OKIA"

func dirRootConfig(t *testing.T) config.Config {
	t.Helper()
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName("simple")
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())
	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

func dirRootTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "src", "nested"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "src", "nested", "config.py"),
		[]byte("key = \""+dirRootSecret+"\"\n"),
		0o644,
	))
	return root
}

func scanDir(t *testing.T, detector *Detector, cfg *config.Config, source string) []report.Finding {
	t.Helper()
	findings, err := detector.DetectSource(context.Background(), &sources.Files{
		Config: cfg,
		Path:   source,
		Sema:   detector.Sema,
	})
	require.NoError(t, err)
	return findings
}

func TestDirScanFindsTheSecretUnderAnyRootSpelling(t *testing.T) {
	cfg := dirRootConfig(t)
	root := dirRootTree(t)

	findings := scanDir(t, NewDetector(cfg), &cfg, root)
	require.Len(t, findings, 1)
	assert.Equal(t, filepath.ToSlash(filepath.Join(root, "src", "nested", "config.py")), findings[0].File,
		"the reported path is unchanged: spelled the way the root was given")
}

func TestGitleaksIgnoreMatchesRelativeToTheScanRoot(t *testing.T) {
	cfg := dirRootConfig(t)
	root := dirRootTree(t)

	// The entry a user gets from `gitleaks dir .`, and what the docs show.
	ignore := filepath.Join(root, ".gitleaksignore")
	require.NoError(t, os.WriteFile(ignore, []byte("src/nested/config.py:aws-access-key:1\n"), 0o644))

	detector := NewDetector(cfg)
	require.NoError(t, detector.AddGitleaksIgnore(ignore))
	assert.Empty(t, scanDir(t, detector, &cfg, root), "an absolute root must honour the same entry")

	// An entry for a different line is still not a match.
	require.NoError(t, os.WriteFile(ignore, []byte("src/nested/config.py:aws-access-key:2\n"), 0o644))
	detector = NewDetector(cfg)
	require.NoError(t, detector.AddGitleaksIgnore(ignore))
	assert.Len(t, scanDir(t, detector, &cfg, root), 1)
}

func TestAllowlistPathsMatchRelativeToTheScanRoot(t *testing.T) {
	cfg := dirRootConfig(t)
	root := dirRootTree(t)

	allowlist := &config.Allowlist{
		Paths: []*regexp.Regexp{regexp.MustCompile(`^src/nested/`)},
	}
	require.NoError(t, allowlist.Validate())
	cfg.Allowlists = append(cfg.Allowlists, allowlist)

	assert.Empty(t, scanDir(t, NewDetector(cfg), &cfg, root),
		"an anchored allowlist path is written against the root and must apply to an absolute root")
}

func TestBaselineInsideTheScanRootIsNotScanned(t *testing.T) {
	cfg := dirRootConfig(t)
	root := dirRootTree(t)

	// Record a baseline into the tree, the way `--report-path` inside the
	// repository does.
	first := scanDir(t, NewDetector(cfg), &cfg, root)
	require.Len(t, first, 1)
	baseline := filepath.Join(root, "baseline.json")
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(baseline, encoded, 0o644))

	detector := NewDetector(cfg)
	require.NoError(t, detector.AddBaseline(baseline, root))
	findings := scanDir(t, detector, &cfg, root)
	for _, finding := range findings {
		assert.NotContains(t, finding.File, "baseline.json",
			"the baseline report itself was scanned and its secrets reported as new")
	}
	assert.Empty(t, findings, "everything is in the baseline")
}

func TestBaselineRecordedWithADotRootMatchesAnAbsoluteRoot(t *testing.T) {
	cfg := dirRootConfig(t)
	root := dirRootTree(t)

	// `gitleaks dir . --report-path baseline.json`, run inside the tree.
	t.Chdir(root)
	first := scanDir(t, NewDetector(cfg), &cfg, ".")
	require.Len(t, first, 1)
	require.Equal(t, "src/nested/config.py", first[0].File)
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("baseline.json", encoded, 0o644))

	// `gitleaks dir /abs/path --baseline-path /abs/path/baseline.json`, the
	// invocation a container or a CI job makes.
	detector := NewDetector(cfg)
	require.NoError(t, detector.AddBaseline(filepath.Join(root, "baseline.json"), root))
	assert.Empty(t, scanDir(t, detector, &cfg, root))

	// And the other way round: a baseline recorded against the absolute root
	// still matches a `dir .` scan.
	require.NoError(t, os.Remove("baseline.json"))
	absolute := scanDir(t, NewDetector(cfg), &cfg, root)
	require.Len(t, absolute, 1)
	encoded, err = json.Marshal(absolute)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("baseline.json", encoded, 0o644))
	detector = NewDetector(cfg)
	require.NoError(t, detector.AddBaseline("baseline.json", "."))
	assert.Empty(t, scanDir(t, detector, &cfg, "."))
}

func TestConfigInsideTheScanRootIsNotScanned(t *testing.T) {
	cfg := dirRootConfig(t)
	root := dirRootTree(t)

	// The default config location is joined onto the root, as cmd does.
	cfg.Path = filepath.Join(root, ".gitleaks.toml")
	require.NoError(t, os.WriteFile(cfg.Path, []byte("# "+dirRootSecret+"\n"), 0o644))

	findings := scanDir(t, NewDetector(cfg), &cfg, root)
	require.Len(t, findings, 1)
	assert.NotContains(t, findings[0].File, ".gitleaks.toml")
}
