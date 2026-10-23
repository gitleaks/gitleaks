package sources

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// collectRawFragments runs Fragments on f and concatenates the raw content of
// every yielded fragment.
func collectRawFragments(t *testing.T, f *File) string {
	t.Helper()

	var sb strings.Builder
	err := f.Fragments(context.Background(), func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		sb.WriteString(fragment.Raw)
		return nil
	})
	require.NoError(t, err)

	return sb.String()
}

// TestFileFragments_PlaintextWithArchiveLikeName is a regression test for
// https://github.com/gitleaks/gitleaks/issues/2316: a plain-text file whose
// name merely contains an archive extension (the archives library matches the
// extension as a substring of the filename) was routed into archive
// extraction and silently yielded zero fragments, so secrets in it were
// missed. The file must be scanned as plain text instead.
func TestFileFragments_PlaintextWithArchiveLikeName(t *testing.T) {
	const secret = `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`

	cases := []string{
		"notes.7z.txt",
		"data.zipx",
		"x.brotli",
		"secret.xzabc",
		"notes.gz.txt",
		"backup.tar.gz.txt",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := &File{
				Content:         strings.NewReader("here is a secret\n" + secret + "\n"),
				Path:            name,
				MaxArchiveDepth: 2,
			}

			raw := collectRawFragments(t, f)
			require.Contains(t, raw, "AKIAIOSFODNN7EXAMPLE",
				"plain-text file %q must be scanned, not silently skipped", name)
		})
	}
}

// TestFileFragments_RealZipStillExtracted guards the other side of the fix:
// a genuine zip archive must still be extracted and its inner files scanned.
func TestFileFragments_RealZipStillExtracted(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.Create("secret.txt")
	require.NoError(t, err)
	_, err = fw.Write([]byte("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	f := &File{
		Content:         bytes.NewReader(buf.Bytes()),
		Path:            "real.zip",
		MaxArchiveDepth: 2,
	}

	raw := collectRawFragments(t, f)
	require.Contains(t, raw, "AKIAIOSFODNN7EXAMPLE",
		"real zip archive must still be extracted")
}

// TestFileFragments_RealGzipStillDecompressed guards the decompressor path:
// a genuine gzip file must still be decompressed and scanned.
func TestFileFragments_RealGzipStillDecompressed(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write([]byte("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	f := &File{
		Content:         bytes.NewReader(buf.Bytes()),
		Path:            "real.gz",
		MaxArchiveDepth: 2,
	}

	raw := collectRawFragments(t, f)
	require.Contains(t, raw, "AKIAIOSFODNN7EXAMPLE",
		"real gzip file must still be decompressed")
}
