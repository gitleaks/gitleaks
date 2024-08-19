package detect

import (
	"bufio"
	"io"

	"github.com/zricethezav/gitleaks/v8/report"
)

// DetectReader accepts an io.Reader and a buffer size for the reader in KB
func (d *Detector) DetectReader(r io.Reader, bufSize int) ([]report.Finding, error) {
	reader := bufio.NewReader(r)
	buf := make([]byte, 0, 1000*bufSize)
	findings := []report.Finding{}

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
				findings = append(findings, finding)
				if d.Verbose {
					printFinding(finding, d.NoColor)
				}
			}
		}

		if err != nil {
			if err != io.EOF {
				return findings, err
			}
			break
		}
	}

	return findings, nil
}
