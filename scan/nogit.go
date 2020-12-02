package scan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/zricethezav/gitleaks/v7/report"

	"golang.org/x/sync/errgroup"
)

// NoGitScanner is a scanner that absolutely despises git
type NoGitScanner struct {
	BaseScanner
	leakChan chan report.Leak
	leakWG   *sync.WaitGroup
	leaks    []report.Leak
}

// NewNoGitScanner creates and returns a nogit scanner. This is used for scanning files and directories
func NewNoGitScanner(base BaseScanner) *NoGitScanner {
	ngs := &NoGitScanner{
		BaseScanner: base,
		leakChan:    make(chan report.Leak),
		leakWG:      &sync.WaitGroup{},
	}

	go ngs.receiveLeaks()

	ngs.scannerType = typeNoGitScanner

	return ngs
}

// Scan kicks off a NoGitScanner Scan
func (ngs *NoGitScanner) Scan() (report.Report, error) {
	var scannerReport report.Report

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
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			scanner := bufio.NewScanner(f)
			line := 0
			for scanner.Scan() {
				line++
				leaks := checkRules(ngs.BaseScanner, emptyCommit(), "", f.Name(), scanner.Text())
				for _, leak := range leaks {
					leak.LineNumber = line
					if ngs.opts.Verbose {
						logLeak(leak, ngs.opts.Redact)
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
	scannerReport.Leaks = ngs.leaks

	return scannerReport, nil
}

func (ngs *NoGitScanner) receiveLeaks() {
	for leak := range ngs.leakChan {
		ngs.leaks = append(ngs.leaks, leak)
		ngs.leakWG.Done()
	}
}
