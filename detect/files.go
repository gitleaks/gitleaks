package detect

import (
	"os"
	"sync"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// DetectFiles runs detections against a chanel of scan targets
//
// Deprecated: Use sources.Files.Fragments() and Detector.DetectSource() instead
func (d *Detector) DetectFiles(scanTargets <-chan sources.ScanTarget) ([]report.Finding, error) {
	var wg sync.WaitGroup

	for scanTarget := range scanTargets {
		wg.Add(1)

		d.Sema.Go(func() error {
			defer wg.Done()

			logger := logging.With().Str("path", scanTarget.Path).Logger()
			logger.Trace().Msg("scanning path:")

			f, err := os.Open(scanTarget.Path)
			if err != nil {
				if os.IsPermission(err) {
					logger.Warn().Msg("skipping file: permission denied:")
				}
				return nil
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				logger.Error().Msgf("skipping file: could not get info: %s: ", err)
				return nil
			}

			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping file: size=0")
				return nil
			}

			// Too large; nothing to do here.
			if d.MaxTargetMegaBytes > 0 {
				rawLength := info.Size() / 1000000
				if rawLength > int64(d.MaxTargetMegaBytes) {
					logger.Warn().Msgf(
						"skipping file: too large: max_size=%dMiB, size=%dMiB",
						d.MaxTargetMegaBytes, rawLength,
					)
					return nil
				}
			}

			// Convert this to a file source
			file := sources.File{
				Content: f,
				Path:    scanTarget.Path,
				Symlink: scanTarget.Symlink,
			}

			return file.Fragments(func(fragment sources.Fragment, err error) error {
				if err != nil {
					logging.Error().Msg(err.Error())
					return nil
				}

				for _, finding := range d.Detect(Fragment(fragment)) {
					d.AddFinding(finding)
				}
				return nil
			})
		})
	}

	wg.Wait()
	return d.findings, nil
}
