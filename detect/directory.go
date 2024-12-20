package detect

import (
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/h2non/filetype"
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const maxPeekSize = 25 * 1_000 // 10kb

func (d *Detector) DetectFiles(paths <-chan sources.ScanTarget) ([]report.Finding, error) {
	for pa := range paths {
		d.Sema.Go(func() error {
			logger := log.With().Str("path", pa.Path).Logger()
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

			// Buffer to hold file chunks
			buf := make([]byte, chunkSize)
			totalLines := 0
			for {
				n, err := f.Read(buf)
				if n > 0 {
					// TODO: optimization could be introduced here
					if mimetype, err := filetype.Match(buf[:n]); err != nil {
						return nil
					} else if mimetype.MIME.Type == "application" {
						return nil // skip binary files
					}

					// If the chunk doesn't end in a newline, peek |maxPeekSize| until we find one.
					// This hopefully avoids splitting
					// See: https://github.com/gitleaks/gitleaks/issues/1651
					var (
						peekBuf      = bytes.NewBuffer(buf[:n])
						tempBuf      = make([]byte, 1)
						newlineCount = 0 // Tracks consecutive newlines
					)
					for {
						data := peekBuf.Bytes()
						if len(data) == 0 {
							break
						}

						// Check if the last character is a newline.
						lastChar := data[len(data)-1]
						if lastChar == '\n' || lastChar == '\r' {
							newlineCount++

							// Stop if two consecutive newlines are found
							if newlineCount >= 2 {
								break
							}
						} else {
							newlineCount = 0 // Reset if a non-newline character is found
						}

						// Stop growing the buffer if it reaches maxSize
						if (peekBuf.Len() - n) >= maxPeekSize {
							break
						}

						// Read additional data into a temporary buffer
						m, readErr := f.Read(tempBuf)
						if m > 0 {
							peekBuf.Write(tempBuf[:m])
						}

						// Stop if EOF is reached
						if readErr != nil {
							if readErr == io.EOF {
								break
							}
							return readErr
						}
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
