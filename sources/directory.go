package sources

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/fatih/semgroup"
	"github.com/rs/zerolog/log"
)

type ScanTarget struct {
	Path    string
	Symlink string
}

func DirectoryTargets(source string, s *semgroup.Group, followSymlinks bool) (<-chan ScanTarget, error) {
	paths := make(chan ScanTarget)
	s.Go(func() error {
		defer close(paths)
		return filepath.Walk(source,
			func(path string, fInfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fInfo.Name() == ".git" && fInfo.IsDir() {
					return filepath.SkipDir
				}
				if fInfo.Size() == 0 {
					return nil
				}
				if fInfo.Mode().IsRegular() {
					paths <- ScanTarget{
						Path:    path,
						Symlink: "",
					}
				}
				if fInfo.Mode().Type() == fs.ModeSymlink && followSymlinks {
					realPath, err := filepath.EvalSymlinks(path)
					if err != nil {
						return err
					}
					realPathFileInfo, _ := os.Stat(realPath)
					if realPathFileInfo.IsDir() {
						log.Debug().Msgf("found symlinked directory: %s -> %s [skipping]", path, realPath)
						return nil
					}
					paths <- ScanTarget{
						Path:    realPath,
						Symlink: path,
					}
				}
				return nil
			})
	})
	return paths, nil
}
