package sources

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

// newFilesSource builds a Files source rooted at dir.
func newFilesSource(ctx context.Context, dir string) *Files {
	cfg := &config.Config{}
	return &Files{
		Config:      cfg,
		Path:        dir,
		Sema:        semgroup.NewGroup(ctx, 4),
		MaxFileSize: 1 << 20,
	}
}

// drainFragments consumes every fragment and returns the source's error.
func drainFragments(t *testing.T, s *Files) error {
	t.Helper()
	return s.Fragments(context.Background(), func(Fragment, error) error { return nil })
}

// TestUnreadableFileIsReportedNotSilentlySkipped is the case from gitleaks#2232.
//
// A file gitleaks cannot open is a file it did not scan. Returning nil there
// meant the open failure could never reach DetectSource's error, so
// findingSummaryAndExit took its err == nil branch and printed the plain
// "no leaks found" with exit 0 over a scan that had skipped files. The
// partial-scan message and non-zero exit already existed in cmd/root.go; they
// were simply unreachable from the most common failure.
func TestUnreadableFileIsReportedNotSilentlySkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}

	dir := t.TempDir()
	readable := filepath.Join(dir, "readable.txt")
	require.NoError(t, os.WriteFile(readable, []byte("nothing secret here\n"), 0o600))
	locked := filepath.Join(dir, "locked.txt")
	require.NoError(t, os.WriteFile(locked, []byte("aws_key = AKIAIOSFODNN7EXAMPLE\n"), 0o600))
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	err := drainFragments(t, newFilesSource(context.Background(), dir))

	require.Error(t, err, "an unreadable file left the scan reporting success")
	require.Contains(t, err.Error(), "locked.txt", "the error should name the file that was skipped")
}

// TestAllReadableFilesReportNoError is the pairing. A source that always
// returned an error would make every scan look partial, which is the same
// loss of signal in the opposite direction.
func TestAllReadableFilesReportNoError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world\n"), 0o600))

	require.NoError(t, drainFragments(t, newFilesSource(context.Background(), dir)))
}

// TestReadableFilesAreStillScannedAlongsideAnUnreadableOne guards the choice
// to keep going: the scan must cover everything it can reach, and report the
// gap at the end, rather than stopping at the first file it cannot open.
func TestReadableFilesAreStillScannedAlongsideAnUnreadableOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits behave differently on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}

	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("content\n"), 0o600))
	}
	locked := filepath.Join(dir, "locked.txt")
	require.NoError(t, os.WriteFile(locked, []byte("content\n"), 0o600))
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	// Atomic: the callback runs on s.Sema's goroutines, one per file.
	var scanned atomic.Int64
	s := newFilesSource(context.Background(), dir)
	err := s.Fragments(context.Background(), func(Fragment, error) error {
		scanned.Add(1)
		return nil
	})

	require.Error(t, err)
	require.Equal(t, int64(3), scanned.Load(), "the readable files must still be scanned")
}

// TestEmptyDirectoryIsNotAnError keeps the signal specific: nothing to read is
// not the same fact as something that could not be read.
func TestEmptyDirectoryIsNotAnError(t *testing.T) {
	require.NoError(t, drainFragments(t, newFilesSource(context.Background(), t.TempDir())))
}
