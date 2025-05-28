package detect

import (
	"context"
	"io"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// DetectReader accepts an io.Reader and a buffer size for the reader in KB
//
// Deprecated: Use sources.File with no path defined and Detector.DetectSource instead
func (d *Detector) DetectReader(r io.Reader, bufSize int) ([]report.Finding, error) {
	var findings []report.Finding
	file := sources.File{
		Content:         r,
		Buffer:          make([]byte, 1000*bufSize),
		MaxArchiveDepth: d.MaxArchiveDepth,
	}

	ctx := context.Background()
	err := file.Fragments(ctx, func(fragment sources.Fragment, err error) error {
		if err != nil {
			return err
		}

		for _, finding := range d.Detect(Fragment(fragment)) {
			findings = append(findings, finding)
			if d.Verbose {
				printFinding(finding, d.NoColor)
			}
		}

		return nil
	})

	return findings, err
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
//
// Deprecated: Use sources.File.Fragments(context.Context, FragmentsFunc) instead
func (d *Detector) StreamDetectReader(r io.Reader, bufSize int) (<-chan report.Finding, <-chan error) {
	findingsCh := make(chan report.Finding, 1)
	errCh := make(chan error, 1)
	file := sources.File{
		Content:         r,
		Buffer:          make([]byte, 1000*bufSize),
		MaxArchiveDepth: d.MaxArchiveDepth,
	}

	go func() {
		defer close(findingsCh)
		defer close(errCh)

		ctx := context.Background()
		errCh <- file.Fragments(ctx, func(fragment sources.Fragment, err error) error {
			if err != nil {
				return err
			}

			for _, finding := range d.Detect(Fragment(fragment)) {
				findingsCh <- finding
				if d.Verbose {
					printFinding(finding, d.NoColor)
				}
			}

			return nil
		})

	}()

	return findingsCh, errCh
}
