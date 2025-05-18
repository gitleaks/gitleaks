package sources

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"

	"github.com/zricethezav/gitleaks/v8/logging"
)

// File implements Source for scanning a reader with a path
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// ChunkSize allows you to set the size of the chunks processed for this file
	// the default is the 'chunkSize' constant in the sources.go file
	ChunkSize int
}

func (s *File) Fragments(yield func(Fragment, error) error) error {
	if s.ChunkSize == 0 {
		s.ChunkSize = chunkSize
	}

	var (
		// Buffer to hold file chunks
		reader     = bufio.NewReaderSize(s.Content, s.ChunkSize)
		buf        = make([]byte, s.ChunkSize)
		totalLines = 0
	)

	for {
		n, err := reader.Read(buf)
		if n == 0 {
			if err != nil && err != io.EOF {
				return yield(Fragment{}, fmt.Errorf("could not read file: %w", err))
			}

			return nil
		}

		// Only check the filetype at the start of file.
		if totalLines == 0 {
			// TODO: could other optimizations be introduced here?
			if mimetype, err := filetype.Match(buf[:n]); err != nil {
				return yield(
					Fragment{},
					fmt.Errorf("could not read file: could not determine type: %w", err),
				)
			} else if mimetype.MIME.Type == "application" {
				logging.Debug().Msgf(
					"skipping file: binary file: mime_type=%q",
					mimetype.MIME.Value,
				)
				return nil
			}
		}

		// Try to split chunks across large areas of whitespace, if possible.
		peekBuf := bytes.NewBuffer(buf[:n])
		if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
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
			logging.Warn().Msgf("issue reading file: %s", err)
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
