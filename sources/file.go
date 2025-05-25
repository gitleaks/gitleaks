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

	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
type seekReaderAt interface {
	io.ReaderAt
	io.Seeker
}

// File implements Source for scanning a reader with a path
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading the content in chunks
	Buffer []byte
}

// Fragments yields fragments for the this source
func (s *File) Fragments(yield FragmentsFunc) error {
	ctx := context.Background()
	format, _, err := archives.Identify(ctx, s.Path, nil)

	if err == nil && format != nil {
		if extractor, ok := format.(archives.Extractor); ok {
			return s.extractorFragments(ctx, extractor, s.Content, yield)
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			return s.decompressorFragments(decompressor, s.Content, yield)
		}
		logging.Warn().Str("path", s.Path).Msg("skipping unkown archive type")
	}

	return s.fileFragments(s.Content, yield)
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) error {
	if _, isSeekReaderAt := reader.(seekReaderAt); !isSeekReaderAt {
		switch extractor.(type) {
		case archives.SevenZip, archives.Zip:
			tmpfile, err := os.CreateTemp("", "gitleaks-archive-")
			if err != nil {
				logging.Error().Str("path", s.Path).Msg("could not create tmp file")
				return nil
			}
			defer os.Remove(tmpfile.Name())
			defer tmpfile.Close()

			_, err = io.Copy(tmpfile, reader)
			if err != nil {
				logging.Error().Str("path", s.Path).Msg("could not copy archive file")
				return nil
			}

			reader = bufio.NewReader(tmpfile)
		}
	}

	return extractor.Extract(ctx, reader, func(ctx context.Context, d archives.FileInfo) error {
		if d.IsDir() {
			return nil
		}

		// Setup paths for the subsource
		path := filepath.Join(s.Path, d.Name())
		symlink := ""
		if len(s.Symlink) > 0 {
			symlink = filepath.Join(s.Symlink, d.Name())
		}

		innerReader, err := d.Open()
		if err != nil {
			logging.Error().Str("path", path).Err(err).Msg("could not open archive inner file")
			return nil
		}

		file := &File{
			Content: innerReader,
			Path:    path,
			Symlink: symlink,
		}

		if err := file.Fragments(yield); err != nil {
			innerReader.Close()
			return err
		}

		innerReader.Close()
		return nil
	})
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) error {
	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		return err
	}

	if err := s.fileFragments(innerReader, yield); err != nil {
		innerReader.Close()
		return err
	}

	innerReader.Close()
	return nil
}

// fileFragments reads the file into fragments to scan
func (s *File) fileFragments(reader io.Reader, yield FragmentsFunc) error {
	// TODO: would a sync.Pool of default bytes buffers make sense here
	// also make sure the buf wouldn't be grown unexpectedly
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	totalLines := 0
	for {
		n, err := reader.Read(s.Buffer)
		if n == 0 {
			if err != nil && err != io.EOF {
				return yield(Fragment{}, fmt.Errorf("could not read file: %w", err))
			}

			return nil
		}

		// Only check the filetype at the start of file.
		if totalLines == 0 {
			// TODO: could other optimizations be introduced here?
			if mimetype, err := filetype.Match(s.Buffer[:n]); err != nil {
				return yield(
					Fragment{},
					fmt.Errorf("could not read file: could not determine type: %w", err),
				)
			} else if mimetype.MIME.Type == "application" {
				logging.Debug().Str(
					"mime_type", mimetype.MIME.Value,
				).Str(
					"path", s.Path,
				).Msgf(
					"skipping binary file",
				)
				return nil
			}
		}

		// Try to split chunks across large areas of whitespace, if possible.
		peekBuf := bytes.NewBuffer(s.Buffer[:n])
		if err := readUntilSafeBoundary(bufio.NewReader(s.Content), n, maxPeekSize, peekBuf); err != nil {
			return yield(
				Fragment{},
				fmt.Errorf("could not read file: could not read until safe boundry: %w", err),
			)
		}

		fragment := Fragment{
			Raw:       peekBuf.String(),
			Bytes:     peekBuf.Bytes(),
			StartLine: totalLines + 1,
		}

		// Count the number of newlines in this chunk
		totalLines += strings.Count(fragment.Raw, "\n")

		if len(s.Symlink) > 0 {
			fragment.SymlinkFile = s.Symlink
		}

		if isWindows {
			fragment.FilePath = filepath.ToSlash(s.Path)
			fragment.SymlinkFile = filepath.ToSlash(s.Symlink)
			fragment.WindowsFilePath = s.Path
		} else {
			fragment.FilePath = s.Path
		}

		// log errors but still scan since there's content
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
