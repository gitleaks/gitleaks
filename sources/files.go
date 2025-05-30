package sources

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/fatih/semgroup"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// TODO: remove this in v9 and have scanTargets yield file sources
type ScanTarget struct {
	Path    string
	Symlink string
}

// Deprecated: Use Files and detector.DetectSource instead
func DirectoryTargets(sourcePath string, s *semgroup.Group, followSymlinks bool, allowlists []*config.Allowlist) (<-chan ScanTarget, error) {
	paths := make(chan ScanTarget)

	// create a Files source
	files := Files{
		FollowSymlinks: followSymlinks,
		Path:           sourcePath,
		Sema:           s,
		Config: &config.Config{
			Allowlists: allowlists,
		},
	}

	s.Go(func() error {
		err := files.scanTargets(func(scanTarget ScanTarget, err error) error {
			paths <- scanTarget
			return nil
		})
		close(paths)
		return err
	})

	return paths, nil
}

// Files is a source for yielding fragments from a collection of files
type Files struct {
	Config          *config.Config
	FollowSymlinks  bool
	MaxFileSize     int
	Path            string
	Sema            *semgroup.Group
	MaxArchiveDepth int
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(yield func(ScanTarget, error) error) error {
	return filepath.WalkDir(s.Path, func(path string, d fs.DirEntry, err error) error {
		scanTarget := ScanTarget{Path: path}
		logger := logging.With().Str("path", path).Logger()

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logger.Warn().Err(errors.New("permission denied")).Msg("skipping directory")
				return filepath.SkipDir
			}
			logger.Warn().Err(err).Msg("skipping")
			return nil
		}

		info, err := d.Info()
		if err != nil {
			if d.IsDir() {
				logger.Error().Err(err).Msg("skipping directory: could not get info")
				return filepath.SkipDir
			}
			logger.Error().Err(err).Msg("skipping file: could not get info")
			return nil
		}

		if !d.IsDir() {
			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if s.MaxFileSize > 0 && info.Size() > int64(s.MaxFileSize) {
				logger.Warn().Msgf(
					"skipping file: too large max_size=%dMB, size=%dMB",
					s.MaxFileSize/1_000_000, info.Size()/1_000_000,
				)
				return nil
			}
		}

		// set the initial scan target values
		if d.Type() == fs.ModeSymlink {
			if !s.FollowSymlinks {
				logger.Debug().Msg("skipping symlink: follow symlinks disabled")
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logger.Error().Err(err).Msg("skipping symlink: could not evaluate")
				return nil
			}
			if realPathFileInfo, _ := os.Stat(realPath); realPathFileInfo.IsDir() {
				logger.Debug().Str("target", realPath).Msgf("skipping symlink: target is directory")
				return nil
			}
			scanTarget = ScanTarget{
				Path:    realPath,
				Symlink: path,
			}
		}

		// handle dir cases (mainly just see if it should be skipped
		if info.IsDir() {
			if shouldSkipPath(s.Config, path) {
				logger.Debug().Msg("skipping directory: global allowlist")
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipPath(s.Config, path) {
			logger.Debug().Msg("skipping file: global allowlist")
			return nil
		}

		return yield(scanTarget, nil)
	})
}

// Fragments yields fragments from files discovered under the path
func (s *Files) Fragments(ctx context.Context, yield FragmentsFunc) error {
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
				Content:         f,
				Path:            scanTarget.Path,
				Symlink:         scanTarget.Symlink,
				Config:          s.Config,
				MaxArchiveDepth: s.MaxArchiveDepth,
			}

			err = file.Fragments(ctx, yield)
			// Avoiding a defer in a hot loop
			_ = f.Close()
			wg.Done()
			return err
		})

		return nil
	})

	wg.Wait()
	return err
}
