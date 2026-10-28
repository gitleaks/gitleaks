package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateReportFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not meaningful on Windows")
	}

	dir := t.TempDir()

	t.Run("new file is created with 0600", func(t *testing.T) {
		path := filepath.Join(dir, "report.json")
		f, err := createReportFile(path)
		if err != nil {
			t.Fatalf("createReportFile: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Errorf("mode = %o, want 0600", got)
		}
	})

	t.Run("pre-existing file is truncated and tightened to 0600", func(t *testing.T) {
		path := filepath.Join(dir, "existing.json")
		if err := os.WriteFile(path, []byte("old report"), 0644); err != nil {
			t.Fatalf("seed file: %v", err)
		}

		f, err := createReportFile(path)
		if err != nil {
			t.Fatalf("createReportFile: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Errorf("mode = %o, want 0600", got)
		}
		if info.Size() != 0 {
			t.Errorf("size = %d, want 0 (truncated)", info.Size())
		}
	})
}
