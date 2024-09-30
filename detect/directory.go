package detect

import (
	"github.com/h2non/filetype"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func (d *Detector) DetectFiles(paths <-chan sources.ScanTarget) ([]report.Finding, error) {
	for p := range paths {
		logger := log.With().Str("path", p.Path).Logger()
		// Check if the file is worth scanning.
		if ok, reason := shouldScanBinaryFile(p.Path); !ok {
			logger.Trace().Str("reason", reason).Msg("Skipping binary file.")
			continue
		}
		logger.Trace().Msg("Scanning path")

		d.Sema.Go(func() error {
			logger := log.With().Str("path", p.Path).Logger()
			logger.Trace().Msg("Scanning path")

			f, err := os.Open(p.Path)
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
				if rawLength > d.MaxTargetMegaBytes {
					logger.Debug().
						Int64("size", rawLength).
						Int64("limit", d.MaxTargetMegaBytes).
						Str("reason", "size").
						Msg("Skipping binary file.")
					return nil
				}
			}

			// Buffer to hold file chunks
			buf := make([]byte, chunkSize)
			totalLines := 0
			for {
				n, err := f.Read(buf)

				// "Callers should always process the n > 0 bytes returned before considering the error err."
				// https://pkg.go.dev/io#Reader
				if n > 0 {
					buf = buf[:n]

					// TODO: optimization could be introduced here
					mimetype, err := filetype.Match(buf)
					if err != nil {
						return err
					}
					if mimetype.Extension != "unknown" {
						log.Info().
							Str("type", mimetype.MIME.Type).
							Str("value", mimetype.MIME.Value).
							Str("subtype", mimetype.MIME.Subtype).
							Str("extension", mimetype.Extension).
							Msg("mimetype info")
					}
					if mimetype.MIME.Type == "application" {
						if !d.ScanBinaryFiles {
							logger.Trace().
								Str("reason", "binary scanning not enabled").
								Msg("Skipping binary file.")
							return nil // skip binary files
						}
						// if err = handleFile(filePath, reader); err != nil {
						//	log.Error().Err(err).
						//		Str("path", filePath).
						//		Msgf("Failed to identify file")
						// }
					}

					// Count the number of newlines in this chunk
					linesInChunk := strings.Count(string(buf[:n]), "\n")
					totalLines += linesInChunk
					fragment := Fragment{
						Raw:      string(buf),
						FilePath: p.Path,
					}
					if p.Symlink != "" {
						fragment.SymlinkFile = p.Symlink
					}

					for _, finding := range d.Detect(fragment) {
						// need to add 1 since line counting starts at 1
						finding.StartLine += (totalLines - linesInChunk) + 1
						finding.EndLine += (totalLines - linesInChunk) + 1
						d.addFinding(finding)
					}
				}
				if err != nil {
					if err != io.EOF {
						return err
					}
					break
				}
			}

			return nil
		})
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}

	return d.findings, nil
}
