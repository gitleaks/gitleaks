package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"
	"github.com/mholt/archives"
	"github.com/rs/zerolog"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
const InnerPathSeparator = "!"

// maxArchiveMagicPeek is how many leading bytes are inspected when sniffing
// a file for an archive signature: 8 bytes cover every supported format
// header, plus the tar "ustar" marker at offset 257.
const maxArchiveMagicPeek = 262

type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading the content in chunks
	Buffer []byte
	// Config is the gitleaks config used for shouldSkipPath. If not set, then
	// shouldSkipPath is ignored
	Config *config.Config
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int
	// archiveDepth is the current archive nesting depth
	archiveDepth int
}

// Fragments yields fragments for the this source
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) error {
	format, _, err := archives.Identify(ctx, s.Path, nil)
	// Process the file as an archive if there's no error && Identify returns
	// a format; but if there's an error or no format, just swallow the error
	// and fall back on treating it like a normal file and let fileFragments
	// decide what to do with it.
	if err == nil && format != nil {
		if handled, err := s.dispatchArchiveFormat(ctx, format, s.Content, yield); handled {
			return err
		}
	}

	// The extension was not recognized as an archive, so try the content:
	// a zip saved as "compressed.other" is still a zip. Content sniffing
	// only runs when archive traversal is enabled, and it is gated on a
	// cheap magic-byte check before the archive library is asked to
	// fully identify the stream. A content match is only a heuristic, so
	// an extraction failure here is logged and skipped instead of failing
	// the scan the way a corrupt named archive would. The reader returned
	// by the sniff is reused on every fall-through path, so bytes peeked
	// from a non-rewindable stream are never lost.
	if format == nil {
		contentFormat, reader, ok := s.identifyArchiveByContent(ctx)
		if ok {
			handled, err := s.dispatchArchiveFormat(ctx, contentFormat, reader, yield)
			if handled {
				if err != nil {
					logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not extract archive identified by content")
				}
				return nil
			}
			return s.fileFragments(ctx, bufio.NewReader(reader), yield)
		}
		if reader != nil {
			return s.fileFragments(ctx, bufio.NewReader(reader), yield)
		}
	}

	return s.fileFragments(ctx, bufio.NewReader(s.Content), yield)
}

// dispatchArchiveFormat routes an identified archive format to extraction
// or decompression. It reports whether the format was handled: when the
// format is not one gitleaks can process, it reports unhandled so the
// caller can fall back to scanning the file as plain text.
func (s *File) dispatchArchiveFormat(ctx context.Context, format archives.Format, reader io.Reader, yield FragmentsFunc) (bool, error) {
	if s.archiveDepth+1 > s.MaxArchiveDepth {
		var event *zerolog.Event

		// Warn if the feature is enabled; else emit a trace log.
		if s.MaxArchiveDepth != 0 {
			event = logging.Warn()
		} else {
			event = logging.Trace()
		}

		event.Str(
			"path", s.FullPath(),
		).Int(
			"max_archive_depth", s.MaxArchiveDepth,
		).Msg("skipping archive: exceeds max archive depth")

		return true, nil
	}
	if extractor, ok := format.(archives.Extractor); ok {
		return true, s.extractorFragments(ctx, extractor, reader, yield)
	}
	if decompressor, ok := format.(archives.Decompressor); ok {
		return true, s.decompressorFragments(ctx, decompressor, reader, yield)
	}
	logging.Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
	return false, nil
}

// identifyArchiveByContent sniffs the content of a file whose extension was
// not recognized as an archive. It first does a single cheap magic-byte
// check and only then asks the archive library to fully identify the
// stream, so the hot path for ordinary files is one small peek. It always
// returns the reader to continue scanning with, positioned at the start of
// the content, so bytes peeked from a non-rewindable stream are not lost
// when the file turns out not to be an archive.
func (s *File) identifyArchiveByContent(ctx context.Context) (archives.Format, io.Reader, bool) {
	if s.Content == nil || s.archiveDepth+1 > s.MaxArchiveDepth {
		return nil, nil, false
	}

	reader := s.Content
	var prefix []byte
	if seeker, ok := s.Content.(io.ReadSeeker); ok {
		buf := make([]byte, maxArchiveMagicPeek)
		n, _ := io.ReadFull(seeker, buf)
		_, _ = seeker.Seek(0, io.SeekStart)
		prefix = buf[:n]
	} else {
		// The reader cannot be rewound, so peek through a buffered
		// reader and keep using it so no bytes are lost.
		buffered := bufio.NewReader(s.Content)
		prefix, _ = buffered.Peek(maxArchiveMagicPeek)
		reader = buffered
	}

	if !hasArchiveMagic(prefix) {
		return nil, reader, false
	}

	format, stream, err := archives.Identify(ctx, s.Path, reader)
	if err != nil || format == nil {
		return nil, stream, false
	}

	return format, stream, true
}

// hasArchiveMagic reports whether prefix looks like the start of a
// supported archive or compressed stream. It is a single prefix check per
// format, not a loop over format matchers: the archive library still does
// the full validation before anything is extracted.
func hasArchiveMagic(prefix []byte) bool {
	switch {
	case bytes.HasPrefix(prefix, []byte("PK\x03\x04")),
		bytes.HasPrefix(prefix, []byte("PK\x05\x06")):
		return true // zip
	case bytes.HasPrefix(prefix, []byte{0x1f, 0x8b}):
		return true // gzip
	case bytes.HasPrefix(prefix, []byte("BZh")):
		return true // bzip2
	case bytes.HasPrefix(prefix, []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}):
		return true // xz
	case bytes.HasPrefix(prefix, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return true // zstd
	case bytes.HasPrefix(prefix, []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}):
		return true // 7z
	case bytes.HasPrefix(prefix, []byte("Rar!\x1a\x07")):
		return true // rar
	case bytes.HasPrefix(prefix, []byte{0x04, 0x22, 0x4d, 0x18}):
		return true // lz4
	case bytes.HasPrefix(prefix, []byte{0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59}):
		return true // snappy framed
	case len(prefix) >= maxArchiveMagicPeek && string(prefix[257:262]) == "ustar":
		return true // tar
	}

	return false
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) error {
	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "gitleaks-archive-")
			if err != nil {
				logging.Error().Str("path", s.FullPath()).Msg("could not create tmp file")
				return nil
			}
			defer func() {
				_ = tmpfile.Close()
				_ = os.Remove(tmpfile.Name())
			}()

			_, err = io.Copy(tmpfile, reader)
			if err != nil {
				logging.Error().Str("path", s.FullPath()).Msg("could not copy archive file")
				return nil
			}

			reader = tmpfile
		}
	}

	return extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		if d.IsDir() {
			return nil
		}

		innerReader, err := d.Open()
		if err != nil {
			logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not open archive inner file")
			return nil
		}
		defer innerReader.Close()
		path := filepath.Clean(d.NameInArchive)

		if s.Config != nil && shouldSkipPath(s.Config, path) {
			logging.Debug().Str("path", s.FullPath()).Msg("skipping file: global allowlist")
			return nil
		}

		file := &File{
			Content:         innerReader,
			Path:            path,
			Symlink:         s.Symlink,
			outerPaths:      append(s.outerPaths, filepath.ToSlash(s.Path)),
			MaxArchiveDepth: s.MaxArchiveDepth,
			archiveDepth:    s.archiveDepth + 1,
		}

		if err := file.Fragments(ctx, yield); err != nil {
			return err
		}

		return nil
	})
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) error {
	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		logging.Error().Str("path", s.FullPath()).Msg("could read compressed file")
		return nil
	}

	if err := s.fileFragments(ctx, bufio.NewReader(innerReader), yield); err != nil {
		_ = innerReader.Close()
		return err
	}

	_ = innerReader.Close()
	return nil
}

// fileFragments reads the file into fragments to yield
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, yield FragmentsFunc) error {
	// Create a buffer if the caller hasn't provided one
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	totalLines := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fragment := Fragment{
				FilePath: s.FullPath(),
			}

			n, err := reader.Read(s.Buffer)
			if n == 0 {
				if err != nil && err != io.EOF {
					return yield(fragment, fmt.Errorf("could not read file: %w", err))
				}

				return nil
			}

			// Only check the filetype at the start of file.
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(s.Buffer[:n]); err != nil {
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not determine type: %w", err),
					)
				} else if mimetype.MIME.Type == "application" {
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", s.FullPath()).
						Msgf("skipping binary file")

					return nil
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(s.Buffer[:n])
			if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
				return yield(
					fragment,
					fmt.Errorf("could not read file: could not read until safe boundary: %w", err),
				)
			}

			fragment.Raw = peekBuf.String()
			fragment.Bytes = peekBuf.Bytes()
			fragment.StartLine = totalLines + 1

			// Count the number of newlines in this chunk
			totalLines += strings.Count(fragment.Raw, "\n")

			if len(s.Symlink) > 0 {
				fragment.SymlinkFile = s.Symlink
			}

			if isWindows {
				fragment.FilePath = filepath.ToSlash(fragment.FilePath)
				fragment.SymlinkFile = filepath.ToSlash(s.Symlink)
				fragment.WindowsFilePath = s.FullPath()
			}

			// log errors but continue since there's content
			if err != nil && err != io.EOF {
				logging.Warn().Err(err).Msgf("issue reading file")
			}

			// Done with the file!
			if err == io.EOF {
				return yield(fragment, nil)
			}

			if err := yield(fragment, err); err != nil {
				return err
			}
		}
	}
}

// FullPath returns the File.Path with any preceding outer paths
func (s *File) FullPath() string {
	if len(s.outerPaths) > 0 {
		return strings.Join(
			// outerPaths have already been normalized to slash
			append(s.outerPaths, s.Path),
			InnerPathSeparator,
		)
	}

	return s.Path
}
