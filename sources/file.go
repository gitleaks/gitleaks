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

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
const InnerPathSeparator = "!"

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
		if s.archiveDepth+1 > s.MaxArchiveDepth {
			// Only warn when the feature is enabled
			if s.MaxArchiveDepth != 0 {
				logging.Warn().Str(
					"path", s.FullPath(),
				).Int(
					"max_archive_depth", s.MaxArchiveDepth,
				).Msg("skipping archive: exceeds max archive depth")
			}
			return nil
		}
		if extractor, ok := format.(archives.Extractor); ok {
			return s.extractorFragments(ctx, extractor, s.Content, yield)
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			return s.decompressorFragments(decompressor, s.Content, yield)
		}
		logging.Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
	}

	return s.fileFragments(bufio.NewReader(s.Content), yield)
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
func (s *File) decompressorFragments(decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) error {
	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		logging.Error().Str("path", s.FullPath()).Msg("could read compressed file")
		return nil
	}

	if err := s.fileFragments(bufio.NewReader(innerReader), yield); err != nil {
		_ = innerReader.Close()
		return err
	}

	_ = innerReader.Close()
	return nil
}

// fileFragments reads the file into fragments to yield
func (s *File) fileFragments(reader *bufio.Reader, yield FragmentsFunc) error {
	// Create a buffer if the caller hasn't provided one
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	totalLines := 0
	for {
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
