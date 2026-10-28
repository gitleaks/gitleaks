package sources

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
)

func TestArchiveMemberHonorsMaxFileSize(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "large.zip")
	require.NoError(t, writeZipFile(archivePath, "large.txt", bytes.Repeat([]byte("A"), 2_000)))

	source := Files{
		Path:            archivePath,
		Sema:            semgroup.NewGroup(context.Background(), 1),
		MaxArchiveDepth: 1,
		MaxFileSize:     1_000,
	}

	var fragments []Fragment
	err := source.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, fragments)
}

func TestCompressedFileHonorsMaxFileSize(t *testing.T) {
	tmpDir := t.TempDir()
	gzipPath := filepath.Join(tmpDir, "large.txt.gz")
	require.NoError(t, writeGzipFile(gzipPath, bytes.Repeat([]byte("A"), 2_000)))

	source := Files{
		Path:            gzipPath,
		Sema:            semgroup.NewGroup(context.Background(), 1),
		MaxArchiveDepth: 1,
		MaxFileSize:     1_000,
	}

	var fragments []Fragment
	err := source.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, fragments)
}

func writeZipFile(path, name string, content []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w, err := zw.Create(name)
	if err != nil {
		_ = zw.Close()
		return err
	}
	if _, err := w.Write(content); err != nil {
		_ = zw.Close()
		return err
	}
	return zw.Close()
}

func writeGzipFile(path string, content []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	if _, err := gw.Write(content); err != nil {
		_ = gw.Close()
		return err
	}
	return gw.Close()
}
