package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	gitignore "github.com/sabhiram/go-gitignore"
	"github.com/stretchr/testify/require"
)

func TestFilesScanTargetsRespectsGitIgnoreDirectoryRule(t *testing.T) {
	tmpDir := t.TempDir()

	require.NoError(t, writeFile(filepath.Join(tmpDir, ".gitignore"), ".angular/\n"))
	require.NoError(t, writeFile(filepath.Join(tmpDir, ".angular", "cache.js"), "secret"))
	require.NoError(t, writeFile(filepath.Join(tmpDir, "src", "main.go"), "package main"))

	gitIgnoreParser, err := gitignore.CompileIgnoreFile(filepath.Join(tmpDir, ".gitignore"))
	require.NoError(t, err)

	src := Files{
		Path:              tmpDir,
		GitIgnoreParser:   gitIgnoreParser,
		GitIgnoreBasePath: tmpDir,
	}

	var scanTargets []string
	err = src.scanTargets(context.Background(), func(scanTarget ScanTarget, err error) error {
		require.NoError(t, err)
		scanTargets = append(scanTargets, filepath.Clean(scanTarget.Path))
		return nil
	})
	require.NoError(t, err)

	require.Contains(t, scanTargets, filepath.Join(tmpDir, "src", "main.go"))
	require.NotContains(t, scanTargets, filepath.Join(tmpDir, ".angular", "cache.js"))
}

func TestFilesScanTargetsRespectsGitIgnoreNegationRule(t *testing.T) {
	tmpDir := t.TempDir()

	gitIgnoreContents := "build/*\n!build/keep.txt\n"
	require.NoError(t, writeFile(filepath.Join(tmpDir, ".gitignore"), gitIgnoreContents))
	require.NoError(t, writeFile(filepath.Join(tmpDir, "build", "drop.txt"), "ignore"))
	require.NoError(t, writeFile(filepath.Join(tmpDir, "build", "keep.txt"), "keep"))

	gitIgnoreParser, err := gitignore.CompileIgnoreFile(filepath.Join(tmpDir, ".gitignore"))
	require.NoError(t, err)

	src := Files{
		Path:              tmpDir,
		GitIgnoreParser:   gitIgnoreParser,
		GitIgnoreBasePath: tmpDir,
	}

	var scanTargets []string
	err = src.scanTargets(context.Background(), func(scanTarget ScanTarget, err error) error {
		require.NoError(t, err)
		scanTargets = append(scanTargets, filepath.Clean(scanTarget.Path))
		return nil
	})
	require.NoError(t, err)

	require.Contains(t, scanTargets, filepath.Join(tmpDir, "build", "keep.txt"))
	require.NotContains(t, scanTargets, filepath.Join(tmpDir, "build", "drop.txt"))
}

func TestFilesScanTargetsRespectsGitIgnoreForSingleFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	singleFile := filepath.Join(tmpDir, "single.txt")

	require.NoError(t, writeFile(filepath.Join(tmpDir, ".gitignore"), "single.txt\n"))
	require.NoError(t, writeFile(singleFile, "secret"))

	gitIgnoreParser, err := gitignore.CompileIgnoreFile(filepath.Join(tmpDir, ".gitignore"))
	require.NoError(t, err)

	src := Files{
		Path:            singleFile,
		GitIgnoreParser: gitIgnoreParser,
	}

	var scanTargets []string
	err = src.scanTargets(context.Background(), func(scanTarget ScanTarget, err error) error {
		require.NoError(t, err)
		scanTargets = append(scanTargets, filepath.Clean(scanTarget.Path))
		return nil
	})
	require.NoError(t, err)

	require.NotContains(t, scanTargets, filepath.Clean(singleFile))
}

func writeFile(path, content string) error {
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
