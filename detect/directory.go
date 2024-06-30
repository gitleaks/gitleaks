package detect

import (
	"io"
	"os"
	"strings"

	"github.com/h2non/filetype"
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func (d *Detector) DetectFiles(paths <-chan sources.ScanTarget) ([]report.Finding, error) {
	for pa := range paths {
		p := pa
		d.Sema.Go(func() error {

			f, err := os.Open(p.Path)
			if err != nil {
				return err
			}
			defer f.Close()

			// Get file size
			fileInfo, err := f.Stat()
			if err != nil {
				return err
			}
			fileSize := fileInfo.Size()
			if d.MaxTargetMegaBytes > 0 {
				rawLength := fileSize / 1000000
				if rawLength > int64(d.MaxTargetMegaBytes) {
					log.Debug().Msgf("skipping file: %s scan due to size: %d", p.Path, rawLength)
					return nil
				}
			}

			// Buffer to hold file chunks
			buf := make([]byte, chunkSize)
			// Buffer to hold last few bytes from the previous chunk
			var lastFewBytesBuffer []byte

			totalLines := 0
			for {
				n, err := f.Read(buf)
				if err != nil && err != io.EOF {
					return err
				}
				if n == 0 {
					break
				}

				// TODO: optimization could be introduced here
				mimetype, err := filetype.Match(buf[:n])
				if err != nil {
					return err
				}
				if mimetype.MIME.Type == "application" {
					return nil // skip binary files
				}

				newBufSize := n
				// append last few characters from the previous chunk
				if lastFewBytesBuffer != nil {
					buf = append(lastFewBytesBuffer, buf...)
					newBufSize = n + lastNBytes
					lastFewBytesBuffer = nil
				}

				// Count the number of newlines in this chunk
				linesInChunk := strings.Count(string(buf[:newBufSize]), "\n")
				totalLines += linesInChunk
				fragment := Fragment{
					Raw:      string(buf[:newBufSize]),
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

				// it is possible that the current chunk has some portion of the keyword
				// and the subsequent buffer has the remaining portion of it
				// eg. current buffer ends with "pass" and next buffer starts with "word"
				// to handle such cases add last few bytes from the current buffer
				// and append it at the beginning of the next buffer
				lastFewBytesBuffer = buf[len(buf)-lastNBytes:]
			}

			return nil
		})
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}

	return d.findings, nil
}
