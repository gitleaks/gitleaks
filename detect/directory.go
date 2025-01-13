package detect

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/h2non/filetype"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const maxPeekSize = 25 * 1_000 // 10kb

func (d *Detector) DetectFiles(paths <-chan sources.ScanTarget) ([]report.Finding, error) {
	for pa := range paths {
		d.Sema.Go(func() error {
			logger := logging.With().Str("path", pa.Path).Logger()
			logger.Trace().Msg("Scanning path")

			f, err := os.Open(pa.Path)
			if err != nil {
				if os.IsPermission(err) {
					logger.Warn().Msg("Skipping file: permission denied")
					return nil
				}
				return err
			}
			defer func() {
				_ = f.Close()
			}()

			// Get file size
			fileInfo, err := f.Stat()
			if err != nil {
				return err
			}
			fileSize := fileInfo.Size()
			if d.MaxTargetMegaBytes > 0 {
				rawLength := fileSize / 1000000
				if rawLength > int64(d.MaxTargetMegaBytes) {
					logger.Debug().
						Int64("size", rawLength).
						Msg("Skipping file: exceeds --max-target-megabytes")
					return nil
				}
			}

			var (
				// Buffer to hold file chunks
				reader     = bufio.NewReaderSize(f, chunkSize)
				buf        = make([]byte, chunkSize)
				totalLines = 0
			)
			for {
				n, err := reader.Read(buf)

				// "Callers should always process the n > 0 bytes returned before considering the error err."
				// https://pkg.go.dev/io#Reader
				if n > 0 {
					// Only check the filetype at the start of file.
					if totalLines == 0 {
						// TODO: could other optimizations be introduced here?
						if mimetype, err := filetype.Match(buf[:n]); err != nil {
							return nil
						} else if mimetype.MIME.Type == "application" {
							return nil // skip binary files
						}
					}

					// Try to split chunks across large areas of whitespace, if possible.
					peekBuf := bytes.NewBuffer(buf[:n])
					if readErr := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); readErr != nil {
						return readErr
					}

					// Count the number of newlines in this chunk
					chunk := peekBuf.String()
					linesInChunk := strings.Count(chunk, "\n")
					totalLines += linesInChunk
					fragment := Fragment{
						Raw:      chunk,
						Bytes:    peekBuf.Bytes(),
						FilePath: pa.Path,
					}
					if pa.Symlink != "" {
						fragment.SymlinkFile = pa.Symlink
					}
					for _, finding := range d.Detect(fragment) {
						// need to add 1 since line counting starts at 1
						finding.StartLine += (totalLines - linesInChunk) + 1
						finding.EndLine += (totalLines - linesInChunk) + 1
						d.addFinding(finding)
					}
				}

				if err != nil {
					if err == io.EOF {
						return nil
					}
					return err
				}
			}
		})
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}

	return d.findings, nil
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
