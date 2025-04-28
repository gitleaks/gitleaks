package detect

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/archives"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// IsArchive asks archives.Identify (with a nil stream, so only the filename)
// whether this file would be handled by an Extractor. If Identify returns
// a Format implementing archives.Extractor, we treat it as an archive.
func IsArchive(path string) bool {
	format, _, err := archives.Identify(context.Background(), path, nil)
	if err != nil {
		// no matching format at all
		return false
	}
	_, ok := format.(archives.Extractor)
	return ok
}

// ExtractArchive extracts all files from archivePath into a temp dir.
// Returns the list of ScanTargets (with real file paths) and the temp dir for cleanup.
func ExtractArchive(archivePath string) ([]sources.ScanTarget, string, error) {
	// 1. Create a temp dir
	tmpDir, err := os.MkdirTemp("", "gitleaks-archive-")
	if err != nil {
		return nil, "", err
	}

	// 2. Open the archive
	f, err := os.Open(archivePath)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}
	defer f.Close()

	// 3. Identify format (name-based + header peek)
	ctx := context.Background()
	format, stream, err := archives.Identify(ctx, archivePath, f)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, "", err
	}

	// 4. Ensure it's extractable
	extractor, ok := format.(archives.Extractor)
	if !ok {
		os.RemoveAll(tmpDir)
		return nil, "", fmt.Errorf("format %T is not extractable", format)
	}

	// 5. Walk and extract
	var targets []sources.ScanTarget
	err = extractor.Extract(ctx, stream, func(ctx context.Context, file archives.FileInfo) error {
		name := file.Name()
		// skip macOS metadata and __MACOSX folders
		// TODO add more exceptions here if needed
		base := filepath.Base(name)
		if strings.HasPrefix(base, "._") || strings.HasPrefix(name, "__MACOSX/") {
			return nil
		}

		if file.IsDir() {
			return nil
		}
		// open and copy out
		r, err := file.Open()
		if err != nil {
			return err
		}
		defer r.Close()

		outPath := filepath.Join(tmpDir, file.Name())
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return err
		}
		outFile, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer outFile.Close()

		if _, err := io.Copy(outFile, r); err != nil {
			return err
		}

		targets = append(targets, sources.ScanTarget{Path: outPath})
		return nil
	})

	return targets, tmpDir, err
}
