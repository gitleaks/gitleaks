package detect

import (
	"bufio"
	"bytes"
	"io"

	"github.com/zricethezav/gitleaks/v8/report"
)

// DetectReader accepts an io.Reader and a buffer size for the reader in KB
func (d *Detector) DetectReader(r io.Reader, bufSize int) ([]report.Finding, error) {
	reader := bufio.NewReader(r)
	buf := make([]byte, 1000*bufSize)
	findings := []report.Finding{}

	for {
		n, err := reader.Read(buf)

		// "Callers should always process the n > 0 bytes returned before considering the error err."
		// https://pkg.go.dev/io#Reader
		if n > 0 {
			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(buf[:n])
			if readErr := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); readErr != nil {
				return findings, readErr
			}

			fragment := Fragment{
				Raw: peekBuf.String(),
			}
			for _, finding := range d.Detect(fragment) {
				findings = append(findings, finding)
				if d.Verbose {
					printFinding(finding, d.NoColor)
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return findings, err
		}
	}

	return findings, nil
}
