package scan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"

	"golang.org/x/sync/errgroup"
)

// NoGitScanner is a scanner that absolutely despises git
type NoGitScanner struct {
	opts options.Options
	cfg  config.Config
}

// NewNoGitScanner creates and returns a nogit scanner. This is used for scanning files and directories
func NewNoGitScanner(opts options.Options, cfg config.Config) *NoGitScanner {
	ngs := &NoGitScanner{
		opts: opts,
		cfg:  cfg,
	}

	// no-git scans should ignore .git folders by default
	// issue: https://github.com/zricethezav/gitleaks/issues/474
	// ngs.cfg.Allowlist
	err := ngs.cfg.Allowlist.IgnoreDotGit()
	if err != nil {
		log.Error(err)
		return nil
	}
	return ngs
}

// Scan kicks off a NoGitScanner Scan
func (ngs *NoGitScanner) Scan() (Report, error) {
	var scannerReport Report

	g, _ := errgroup.WithContext(context.Background())
	paths := make(chan string, 100)

	g.Go(func() error {
		defer close(paths)
		return filepath.Walk(ngs.opts.Path,
			func(path string, fInfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fInfo.Mode().IsRegular() {
					paths <- path
				}
				return nil
			})
	})

	leaks := make(chan Leak, 100)

	for path := range paths {
		p := path
		g.Go(func() error {
			if ngs.cfg.Allowlist.FileAllowed(filepath.Base(p)) ||
				ngs.cfg.Allowlist.PathAllowed(p) {
				return nil
			}

			for _, rule := range ngs.cfg.Rules {
				if rule.HasFileOrPathLeakOnly(p) {
					leak := NewLeak("", "Filename or path offender: "+p, defaultLineNumber)
					relPath, err := filepath.Rel(ngs.opts.Path, p)
					if err != nil {
						leak.File = p
					} else {
						leak.File = relPath
					}
					leak.Rule = rule.Description
					leak.Tags = strings.Join(rule.Tags, ", ")

					leak.Log(ngs.opts)

					leaks <- leak
				}
			}

			f, err := os.Open(p) // #nosec
			if err != nil {
				return err
			}
			scanner := bufio.NewScanner(f)
			lineNumber := 0
			for scanner.Scan() {
				lineNumber++
				for _, rule := range ngs.cfg.Rules {
					line := scanner.Text()

					if rule.AllowList.FileAllowed(filepath.Base(p)) ||
						rule.AllowList.PathAllowed(p) {
						continue
					}

					offender := rule.Inspect(line)
					if offender.IsEmpty() {
						continue
					}
					if ngs.cfg.Allowlist.RegexAllowed(line) {
						continue
					}

					if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(p)) {
						continue
					}
					if rule.Path.String() != "" && !rule.HasFilePathLeak(p) {
						continue
					}

					leak := NewLeak(line, offender.ToString(), defaultLineNumber).WithEntropy(offender.EntropyLevel)
					relPath, err := filepath.Rel(ngs.opts.Path, p)
					if err != nil {
						leak.File = p
					} else {
						leak.File = relPath
					}
					leak.LineNumber = lineNumber
					leak.Rule = rule.Description
					leak.Tags = strings.Join(rule.Tags, ", ")

					leak.Log(ngs.opts)

					leaks <- leak
				}
			}
			return f.Close()
		})
	}

	go func() {
		if err := g.Wait(); err != nil {
			log.Error(err)
		}
		close(leaks)
	}()

	for leak := range leaks {
		scannerReport.Leaks = append(scannerReport.Leaks, leak)
	}

	return scannerReport, g.Wait()
}
