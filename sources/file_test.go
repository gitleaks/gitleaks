package sources

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const archiveTestSecret = "SECRET_MARKER_2010"

func collectFragments(t *testing.T, f *File) []Fragment {
	t.Helper()

	var fragments []Fragment
	err := f.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)

	return fragments
}

func fragmentsText(fragments []Fragment) string {
	var buf bytes.Buffer
	for _, f := range fragments {
		buf.WriteString(f.Raw)
	}

	return buf.String()
}

func zipBytes(t *testing.T, name, content string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	require.NoError(t, err)
	_, err = f.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func gzipBytes(t *testing.T, content string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func tarBytes(t *testing.T, name, content string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	require.NoError(t, w.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o600,
		Size: int64(len(content)),
	}))
	_, err := w.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func TestHasArchiveMagic(t *testing.T) {
	cases := []struct {
		name   string
		prefix []byte
		want   bool
	}{
		{name: "zip", prefix: []byte("PK\x03\x04"), want: true},
		{name: "empty zip", prefix: []byte("PK\x05\x06"), want: true},
		{name: "gzip", prefix: []byte{0x1f, 0x8b, 0x08}, want: true},
		{name: "bzip2", prefix: []byte("BZh9"), want: true},
		{name: "xz", prefix: []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, want: true},
		{name: "zstd", prefix: []byte{0x28, 0xb5, 0x2f, 0xfd}, want: true},
		{name: "7z", prefix: []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, want: true},
		{name: "rar v5", prefix: []byte("Rar!\x1a\x07\x01\x00"), want: true},
		{name: "rar v1.5", prefix: []byte("Rar!\x1a\x07\x00"), want: true},
		{name: "lz4", prefix: []byte{0x04, 0x22, 0x4d, 0x18}, want: true},
		{
			name:   "snappy framed",
			prefix: []byte{0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59},
			want:   true,
		},
		{
			name:   "tar",
			prefix: append(bytes.Repeat([]byte{0}, 257), []byte("ustar")...),
			want:   true,
		},
		{name: "plain text", prefix: []byte("hello world\n"), want: false},
		{name: "empty", prefix: []byte{}, want: false},
		{name: "short zip prefix", prefix: []byte("PK"), want: false},
		{name: "almost zip", prefix: []byte("PK\x03\x05"), want: false},
		{name: "almost gzip", prefix: []byte{0x1f, 0x8c}, want: false},
		{
			name:   "tar marker too early",
			prefix: append(bytes.Repeat([]byte{0}, 100), []byte("ustar")...),
			want:   false,
		},
		{
			name:   "tar marker truncated",
			prefix: append(bytes.Repeat([]byte{0}, 257), []byte("usta")...),
			want:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, hasArchiveMagic(c.prefix))
		})
	}
}

func TestFileFragments_ArchiveByContent(t *testing.T) {
	secret := "aws-secret-access-key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" + archiveTestSecret + "\n"

	cases := []struct {
		name     string
		content  []byte
		seekable bool
		depth    int
	}{
		{
			name:     "zip with unknown extension",
			content:  zipBytes(t, "secret.txt", secret),
			seekable: true,
			depth:    2,
		},
		{
			name:     "zip with unknown extension over non-seekable reader",
			content:  zipBytes(t, "secret.txt", secret),
			seekable: false,
			depth:    2,
		},
		{
			name:     "gzip with unknown extension",
			content:  gzipBytes(t, secret),
			seekable: true,
			depth:    2,
		},
		{
			name:     "tar with unknown extension",
			content:  tarBytes(t, "secret.txt", secret),
			seekable: true,
			depth:    2,
		},
		{
			name:     "gzipped tar with unknown extension",
			content:  gzipBytes(t, string(tarBytes(t, "secret.txt", secret))),
			seekable: true,
			depth:    2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var content io.Reader
			if c.seekable {
				content = bytes.NewReader(c.content)
			} else {
				content = bytes.NewBuffer(c.content)
			}

			fragments := collectFragments(t, &File{
				Content:         content,
				Path:            "compressed.other",
				MaxArchiveDepth: c.depth,
			})
			require.NotEmpty(t, fragments)
			require.Contains(t, fragmentsText(fragments), archiveTestSecret)
		})
	}

	t.Run("bzip2 with unknown extension", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("testdata", "bzip2.other"))
		require.NoError(t, err)

		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader(data),
			Path:            "compressed.other",
			MaxArchiveDepth: 2,
		})
		require.NotEmpty(t, fragments)
		require.Contains(t, fragmentsText(fragments), archiveTestSecret)
	})

	t.Run("xz with unknown extension", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("testdata", "xz.other"))
		require.NoError(t, err)

		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader(data),
			Path:            "compressed.other",
			MaxArchiveDepth: 2,
		})
		require.NotEmpty(t, fragments)
		require.Contains(t, fragmentsText(fragments), archiveTestSecret)
	})

	t.Run("nested zip with unknown extensions", func(t *testing.T) {
		inner := zipBytes(t, "secret.txt", secret)
		outer := zipBytes(t, "inner.other", string(inner))

		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader(outer),
			Path:            "outer.other",
			MaxArchiveDepth: 2,
		})
		require.NotEmpty(t, fragments)
		require.Contains(t, fragmentsText(fragments), archiveTestSecret)
		require.Contains(t, fragments[0].FilePath, "secret.txt")
	})

	t.Run("known zip extension still works", func(t *testing.T) {
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader(zipBytes(t, "secret.txt", secret)),
			Path:            "compressed.zip",
			MaxArchiveDepth: 2,
		})
		require.NotEmpty(t, fragments)
		require.Contains(t, fragmentsText(fragments), archiveTestSecret)
	})

	t.Run("archive traversal disabled keeps skipping", func(t *testing.T) {
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader(zipBytes(t, "secret.txt", secret)),
			Path:            "compressed.other",
			MaxArchiveDepth: 0,
		})
		require.Empty(t, fragments)
	})

	t.Run("plain text with unknown extension still scanned", func(t *testing.T) {
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader([]byte(secret)),
			Path:            "notes.other",
			MaxArchiveDepth: 2,
		})
		require.NotEmpty(t, fragments)
		require.Contains(t, fragmentsText(fragments), archiveTestSecret)
	})

	t.Run("binary with unknown extension still skipped", func(t *testing.T) {
		pdf := []byte("%PDF-1.4\n%âãÏÓ\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader(pdf),
			Path:            "document.other",
			MaxArchiveDepth: 2,
		})
		require.Empty(t, fragments)
	})

	t.Run("corrupt archive magic does not panic", func(t *testing.T) {
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader([]byte("PK\x03\x04not a real zip at all")),
			Path:            "compressed.other",
			MaxArchiveDepth: 2,
		})
		require.Empty(t, fragments)
	})

	t.Run("empty file does not panic", func(t *testing.T) {
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader([]byte{}),
			Path:            "empty.other",
			MaxArchiveDepth: 2,
		})
		require.Empty(t, fragments)
	})

	t.Run("tiny plain text file does not panic", func(t *testing.T) {
		fragments := collectFragments(t, &File{
			Content:         bytes.NewReader([]byte("abc")),
			Path:            "tiny.other",
			MaxArchiveDepth: 2,
		})
		require.NotEmpty(t, fragments)
		require.Contains(t, fragmentsText(fragments), "abc")
	})
}
