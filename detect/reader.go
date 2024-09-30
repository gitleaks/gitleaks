package detect

import (
	"bufio"
	"io"

	"github.com/zricethezav/gitleaks/v8/report"
)

// DetectReader accepts an io.Reader and a buffer size for the reader in KB
func (d *Detector) DetectReader(r io.Reader) ([]report.Finding, error) {
	var (
		reader = bufio.NewReader(r)
		buf    = make([]byte, 0, chunkSize)
	)
	for {
		n, err := reader.Read(buf[:cap(buf)])

		// "Callers should always process the n > 0 bytes returned before considering the error err."
		// https://pkg.go.dev/io#Reader
		if n > 0 {
			buf = buf[:n]
			fragment := Fragment{
				Raw: string(buf),
			}
			for _, finding := range d.Detect(fragment) {
				d.addFinding(finding)
			}
		}

		if err != nil {
			if err != io.EOF {
				return d.findings, err
			}
			break
		}
	}

	return d.findings, nil
}
