package sources

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/fatih/semgroup"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

type ScanTarget struct {
	Path    string
	Symlink string
}

// Deprecated: Use Files.Fragments() instead
func DirectoryTargets(sourcePath string, s *semgroup.Group, followSymlinks bool, allowlists []*config.Allowlist) (<-chan ScanTarget, error) {
	paths := make(chan ScanTarget)

	// create a Files source
	source := &Files{
		FollowSymlinks: followSymlinks,
		Path:           sourcePath,
		Sema:           s,
		Config: &config.Config{
			Allowlists: allowlists,
		},
	}

	s.Go(func() error {
		source.scanTargets(func(scanTarget ScanTarget, err error) error {
			paths <- scanTarget
			return nil
		})
		close(paths)
		return nil
	})

	return paths, nil
}

// Files implements Source for scanning file systems
type Files struct {
	Config         *config.Config
	FollowSymlinks bool
	MaxFileSize    int
	Path           string
	Sema           *semgroup.Group
}

func (s *Files) shouldSkip(path string) bool {
	for _, a := range s.Config.Allowlists {
		if a.PathAllowed(path) ||
			// TODO: Remove this in v9.
			// This is an awkward hack to mitigate https://github.com/gitleaks/gitleaks/issues/1641.
			(isWindows && a.PathAllowed(filepath.ToSlash(path))) {
			return true
		}
	}

	return false
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(yield func(ScanTarget, error) error) error {
	return filepath.WalkDir(s.Path, func(path string, d fs.DirEntry, err error) error {
		scanTarget := ScanTarget{Path: path}
		logger := logging.With().Str("path", path).Logger()

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logger.Warn().Msgf("skipping directory: permission denied")
				return filepath.SkipDir
			}
			logger.Error().Msgf("skipping directory: %s", err)
			return nil
		}

		info, err := d.Info()
		if err != nil {
			if d.IsDir() {
				logger.Error().Msgf("skipping directory: could not get info: %s", err)
				return filepath.SkipDir
			}
			logger.Error().Msgf("skipping file: could not get info: %s", err)
			return nil
		}

		if !d.IsDir() {
			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping file: size=0")
				return nil
			}

			// Too large; nothing to do here.
			if s.MaxFileSize > 0 && info.Size() > int64(s.MaxFileSize) {
				logger.Warn().Msgf(
					"skipping file: too large: max_size=%dMiB, size=%dMiB",
					s.MaxFileSize/1000000, info.Size()/1000000,
				)
				return nil
			}
		}

		// set the inital scan target values
		if d.Type() == fs.ModeSymlink {
			if !s.FollowSymlinks {
				logger.Debug().Msg("skipping symlink: follow symlinks disabled")
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logger.Error().Msgf("skipping symlink: could not evaluate: %s", err)
				return nil
			}
			realPathFileInfo, _ := os.Stat(realPath)
			if realPathFileInfo.IsDir() {
				logger.Debug().Msgf("skipping symlink: target is directory: target=%q", realPath)
				return nil
			}
			scanTarget = ScanTarget{
				Path:    realPath,
				Symlink: path,
			}
		}

		// handle dir cases (mainly just see if it should be skipped
		if info.IsDir() {
			if s.shouldSkip(path) {
				logger.Debug().Msg("skipping directory: global allowlist item:")
				return filepath.SkipDir
			}
			if info.Name() == ".git" {
				// TODO: Add this to the config allowlist, instead of hard-coding it.
				logger.Debug().Msg("skipping directory: .git directory always skipped")
				return filepath.SkipDir
			}
			return nil
		}

		if s.shouldSkip(path) {
			logger.Debug().Msg("skipping file: global allowlist item:")
			return nil
		}

		if err := yield(scanTarget, nil); err != nil {
			return err
		}

		return nil
	})
}

func (s *Files) Fragments(yield FragmentsFunc) error {
	var wg sync.WaitGroup

	err := s.scanTargets(func(scanTarget ScanTarget, err error) error {
		wg.Add(1)
		s.Sema.Go(func() error {
			logger := logging.With().Str("path", scanTarget.Path).Logger()
			logger.Trace().Msg("scanning path")

			f, err := os.Open(scanTarget.Path)
			if err != nil {
				if os.IsPermission(err) {
					logger.Warn().Msg("skipping file: permission denied")
				}
				wg.Done()
				return nil
			}

			// Convert this to a file source
			file := File{
				Content: f,
				Path:    scanTarget.Path,
				Symlink: scanTarget.Symlink,
			}

			err = file.Fragments(yield)
			// Avoiding a defer in a hot loop
			f.Close()
			wg.Done()
			return err
		})

		return nil
	})

	wg.Wait()
	return err
}
