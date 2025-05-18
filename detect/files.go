package detect

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h2non/filetype"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// DetectFiles runs detections against a chanel of scan targets
//
// Deprecated: Use sources.Files.Fragments() and Detector.DetectFragments() instead
func (d *Detector) DetectFiles(paths <-chan sources.ScanTarget) ([]report.Finding, error) {
	for pa := range paths {
		d.Sema.Go(func() error {
			source := &sources.Files{
				Config: d.Config
				FollowSymlinks: len(pa.Symlink) > 0
				MaxTargetMegaBytes: d.MaxTargetMegaBytes,
				Path: pa.Path,
				Sema: d.Sema,
			}

			for _, finding := range d.DetectFragments(source.Fragments()) {
				d.AddFinding(finding)
			}
		})
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}

	return d.findings, nil
}
