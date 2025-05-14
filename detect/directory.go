package detect

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const maxPeekSize = 25 * 1_000 // 10kb

// DetectFiles schedules each ScanTarget—file or archive—for concurrent scanning.
func (d *Detector) DetectFiles(paths <-chan sources.ScanTarget) ([]report.Finding, error) {
	for pa := range paths {
		d.Sema.Go(func() error {
			return d.detectScanTarget(pa)
		})
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}
	return d.findings, nil
}

// detectScanTarget handles one ScanTarget: it unpacks archives recursively
// or scans a regular file, always using VirtualPath for reporting.
func (d *Detector) detectScanTarget(scanTarget sources.ScanTarget) error {
	// Choose display path: either VirtualPath (archive chain) or on-disk path.
	display := scanTarget.Path
	if scanTarget.VirtualPath != "" {
		display = scanTarget.VirtualPath
	}
	logger := logging.With().Str("path", display).Logger()
	logger.Trace().Msg("Scanning path")

	// --- Archive branch: extract and reschedule children ---
	if IsArchive(scanTarget.Path) {
		logger.Info().Msg("Found archive")

		targets, tmpdir, err := ExtractArchive(scanTarget.Path)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to extract archive")
			return nil
		}
		// Schedule each extracted file for its own scan, carrying forward VirtualPath.
		for _, t := range targets {
			t := t
			// compute path INSIDE this archive
			rel, rerr := filepath.Rel(tmpdir, t.Path)
			if rerr != nil {
				rel = filepath.Base(t.Path)
			}
			rel = filepath.ToSlash(rel)

			// prepend existing chain or archive base name
			if scanTarget.VirtualPath != "" {
				t.VirtualPath = scanTarget.VirtualPath + "/" + rel
			} else {
				t.VirtualPath = filepath.Base(scanTarget.Path) + "/" + rel
			}

			d.Sema.Go(func() error {
				return d.detectScanTarget(t)
			})
		}

		// cleanup extraction directory
		// if err := os.RemoveAll(tmpdir); err != nil {
		// 	logger.Warn().Err(err).Msg("Failed to remove tempdir")
		// }
		return nil
	}

	// --- Regular file branch ---
	f, err := os.Open(scanTarget.Path)
	if err != nil {
		if os.IsPermission(err) {
			logger.Warn().Msg("Skipping file: permission denied")
			return nil
		}
		return err
	}
	defer f.Close()

	// Skip binary files by sniffing header
	head := make([]byte, 261)
	if n, _ := io.ReadFull(f, head); n > 0 {
		if kind, _ := filetype.Match(head[:n]); kind != filetype.Unknown {
			logger.Debug().Str("kind", kind.Extension).Msg("Skipping binary")
			return nil
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReader(f)
	buf := make([]byte, chunkSize)
	totalLines := 0

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			peekBuf := bytes.NewBuffer(buf[:n])
			if readErr := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); readErr != nil {
				return readErr
			}

			chunk := peekBuf.String()
			linesInChunk := strings.Count(chunk, "\n")

			// build fragment and set FilePath to our display chain
			fragment := Fragment{
				Raw:   chunk,
				Bytes: peekBuf.Bytes(),
			}
			fragment.FilePath = display

			// if this file was itself a symlink
			if scanTarget.Symlink != "" {
				fragment.SymlinkFile = scanTarget.Symlink
			}
			if isWindows {
				fragment.WindowsFilePath = scanTarget.Path
			}

			// run detection and adjust line numbers
			for _, finding := range d.Detect(fragment) {
				finding.StartLine += totalLines + 1
				finding.EndLine += totalLines + 1

				// We have to augment the finding if the source is coming
				// from a archive committed in Git
				if scanTarget.Source == "github-archive" {
					finding.Author = scanTarget.GitInfo.Author
					finding.Commit = scanTarget.GitInfo.Commit
					finding.Email = scanTarget.GitInfo.Email
					finding.Date = scanTarget.GitInfo.Date
					finding.Message = scanTarget.GitInfo.Message
				}

				d.AddFinding(finding)
			}
			totalLines += linesInChunk
		}

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// readUntilSafeBoundary consumes |f| until it finds two consecutive `\n` characters, up to |maxPeekSize|.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)
	if isWhitespace(lastChar) {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return nil
				}
			} else if lastChar == '\r' || lastChar == ' ' || lastChar == '\t' {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if lastChar == '\r' || lastChar == ' ' || lastChar == '\t' {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (peekBuf.Len() - n) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peekBuf.WriteByte(b)
	}
	return nil
}
