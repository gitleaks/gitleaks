package detect

import (
	"io"
	"os"
	"strings"

	"github.com/h2non/filetype"
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

			// Buffer to hold file chunks
			buf := make([]byte, chunkSize)
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

				// Count the number of newlines in this chunk
				linesInChunk := strings.Count(string(buf[:n]), "\n")
				totalLines += linesInChunk
				fragment := Fragment{
					Raw:      string(buf[:n]),
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

			return nil
		})
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}

	return d.findings, nil
}
