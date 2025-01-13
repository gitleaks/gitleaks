package sources

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fatih/semgroup"

	"github.com/zricethezav/gitleaks/v8/logging"
)

type ScanTarget struct {
	Path    string
	Symlink string
}

func DirectoryTargets(source string, s *semgroup.Group, followSymlinks bool, shouldSkip func(string) bool) (<-chan ScanTarget, error) {
	paths := make(chan ScanTarget)
	s.Go(func() error {
		defer close(paths)
		return filepath.Walk(source,
			func(path string, fInfo os.FileInfo, err error) error {
				logger := logging.With().Str("path", path).Logger()

				if err != nil {
					if os.IsPermission(err) {
						// This seems to only fail on directories at this stage.
						logger.Warn().Msg("Skipping directory: permission denied")
						return filepath.SkipDir
					}
					return err
				}

				// Empty; nothing to do here.
				if fInfo.Size() == 0 {
					return nil
				}

				// Unwrap symlinks, if |followSymlinks| is set.
				scanTarget := ScanTarget{
					Path: path,
				}
				if fInfo.Mode().Type() == fs.ModeSymlink {
					if !followSymlinks {
						logger.Debug().Msg("Skipping symlink")
						return nil
					}

					realPath, err := filepath.EvalSymlinks(path)
					if err != nil {
						return err
					}

					realPathFileInfo, _ := os.Stat(realPath)
					if realPathFileInfo.IsDir() {
						logger.Warn().Str("target", realPath).Msg("Skipping symlinked directory")
						return nil
					}

					scanTarget.Path = realPath
					scanTarget.Symlink = path
				}

				// TODO: Also run this check against the resolved symlink?
				skip := shouldSkip(path)
				if fInfo.IsDir() {
					// Directory
					if skip {
						logger.Debug().Msg("Skipping directory due to global allowlist")
						return filepath.SkipDir
					}

					if fInfo.Name() == ".git" {
						// Don't scan .git directories.
						// TODO: Add this to the config allowlist, instead of hard-coding it.
						return filepath.SkipDir
					}
				} else {
					// File
					if skip {
						logger.Debug().Msg("Skipping file due to global allowlist")
						return nil
					}

					paths <- scanTarget
				}
				return nil
			})
	})
	return paths, nil
}
