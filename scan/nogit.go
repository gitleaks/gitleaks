package scan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"golang.org/x/sync/errgroup"
)

// NoGitScanner is a scanner that absolutely despises git
type NoGitScanner struct {
	BaseScanner
	leakChan chan Leak
	leakWG   *sync.WaitGroup
	leaks    []Leak
}

// NewNoGitScanner creates and returns a nogit scanner. This is used for scanning files and directories
func NewNoGitScanner(base BaseScanner) *NoGitScanner {
	ngs := &NoGitScanner{
		BaseScanner: base,
		leakChan:    make(chan Leak),
		leakWG:      &sync.WaitGroup{},
	}

	go ngs.receiveLeaks()

	ngs.scannerType = typeNoGitScanner

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
	paths := make(chan string)
	semaphore := make(chan bool, howManyThreads(ngs.opts.Threads))
	wg := sync.WaitGroup{}

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

	for path := range paths {
		p := path
		wg.Add(1)
		semaphore <- true
		g.Go(func() error {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			if ngs.cfg.Allowlist.FileAllowed(filepath.Base(path)) ||
				ngs.cfg.Allowlist.PathAllowed(path) {
				return nil
			}

			for _, rule := range ngs.cfg.Rules {
				if rule.HasFileOrPathLeakOnly(path) {
					leak := NewLeak("", "Filename or path offender: "+path, defaultLineNumber)
					leak.File = path
					leak.Rule = rule.Description
					leak.Tags = strings.Join(rule.Tags, ", ")

					if ngs.opts.Verbose {
						leak.Log(ngs.opts.Redact)
					}
					ngs.leakWG.Add(1)
					ngs.leakChan <- leak
				}
			}

			f, err := os.Open(p)
			if err != nil {
				return err
			}
			scanner := bufio.NewScanner(f)
			lineNumber := 0
			for scanner.Scan() {
				lineNumber++
				for _, rule := range ngs.cfg.Rules {
					line := scanner.Text()
					offender := rule.Inspect(line)
					if offender == "" {
						continue
					}
					if ngs.cfg.Allowlist.RegexAllowed(line) ||
						rule.AllowList.FileAllowed(filepath.Base(path)) ||
						rule.AllowList.PathAllowed(path) {
						continue
					}

					if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(path)) {
						continue
					}
					if rule.Path.String() != "" && !rule.HasFilePathLeak(path) {
						continue
					}

					leak := NewLeak(line, offender, defaultLineNumber)
					leak.File = path
					leak.LineNumber = lineNumber
					leak.Rule = rule.Description
					leak.Tags = strings.Join(rule.Tags, ", ")
					if ngs.opts.Verbose {
						leak.Log(ngs.opts.Redact)
					}
					ngs.leakWG.Add(1)
					ngs.leakChan <- leak
				}
			}
			return f.Close()
		})
	}

	wg.Wait()
	ngs.leakWG.Wait()

	//err := g.Wait()
	//if err != nil {
	//	return scannerReport, err
	//}

	scannerReport.Leaks = ngs.leaks

	return scannerReport, nil
}

func (ngs *NoGitScanner) receiveLeaks() {
	for leak := range ngs.leakChan {
		ngs.leaks = append(ngs.leaks, leak)
		ngs.leakWG.Done()
	}
}
