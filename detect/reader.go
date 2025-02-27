package detect

import (
	"bufio"
	"bytes"
	"errors"
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

// StreamDetectReader streams the detection results from the provided io.Reader.
// It reads data using the specified buffer size (in KB) and processes each chunk through
// the existing detection logic. Findings are sent down the returned findings channel as soon as
// they are detected, while a separate error channel signals a terminal error (or nil upon successful completion).
// The function returns two channels:
//   - findingsCh: a receive-only channel that emits report.Finding objects as they are found.
//   - errCh: a receive-only channel that emits a single final error (or nil if no error occurred)
//     once the stream ends.
//
// Recommended Usage:
//
//	Since there will only ever be a single value on the errCh, it is recommended to consume the findingsCh
//	first. Once findingsCh is closed, the consumer should then read from errCh to determine
//	if the stream completed successfully or if an error occurred.
//
//	This design avoids the need for a select loop, keeping client code simple.
//
// Example:
//
//	// Assume detector is an instance of *Detector and myReader implements io.Reader.
//	findingsCh, errCh := detector.StreamDetectReader(myReader, 64) // using 64 KB buffer size
//
//	// Process findings as they arrive.
//	for finding := range findingsCh {
//	    fmt.Printf("Found secret: %+v\n", finding)
//	}
//
//	// After the findings channel is closed, check the final error.
//	if err := <-errCh; err != nil {
//	    log.Fatalf("StreamDetectReader encountered an error: %v", err)
//	} else {
//	    fmt.Println("Scanning completed successfully.")
//	}
func (d *Detector) StreamDetectReader(r io.Reader, bufSize int) (<-chan report.Finding, <-chan error) {
	findingsCh := make(chan report.Finding, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(findingsCh)
		defer close(errCh)

		reader := bufio.NewReader(r)
		buf := make([]byte, 1000*bufSize)

		for {
			n, err := reader.Read(buf)

			if n > 0 {
				peekBuf := bytes.NewBuffer(buf[:n])
				if readErr := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); readErr != nil {
					errCh <- readErr
					return
				}

				fragment := Fragment{Raw: peekBuf.String()}
				for _, finding := range d.Detect(fragment) {
					findingsCh <- finding
					if d.Verbose {
						printFinding(finding, d.NoColor)
					}
				}
			}

			if err != nil {
				if errors.Is(err, io.EOF) {
					errCh <- nil
					return
				}
				errCh <- err
				return
			}
		}
	}()

	return findingsCh, errCh
}
