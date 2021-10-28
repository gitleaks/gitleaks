package detect

import (
	"path/filepath"
	"sync"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

// FromGit accepts a gitdiff.File channel (structure output from `git log -p`) and a configuration
// struct. Files from the gitdiff.File channel are then checked against each rule in the configuration to
// check for secrets. If any secrets are found, they are added to the list of findings.
func FromGit(files <-chan *gitdiff.File, cfg config.Config, outputOptions Options) []report.Finding {
	var findings []report.Finding
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	for f := range files {
		wg.Add(1)
		go func(f *gitdiff.File) {
			defer wg.Done()
			if f.IsBinary {
				return
			}

			if f.IsDelete {
				return
			}

			for _, tf := range f.TextFragments {
				if f.TextFragments == nil {
					// https://github.com/gitleaks/gitleaks/issues/11
					continue
				}

				for _, fi := range processBytes(cfg, []byte(tf.Raw(gitdiff.OpAdd)), filepath.Ext(f.NewName)) {
					fi.StartLine += int(tf.NewPosition)
					fi.EndLine += int(tf.NewPosition)
					fi.File = f.NewName
					if f.PatchHeader != nil {
						fi.Commit = f.PatchHeader.SHA
						fi.Message = f.PatchHeader.Message()
						if f.PatchHeader.Author != nil {
							fi.Author = f.PatchHeader.Author.Name
							fi.Email = f.PatchHeader.Author.Email
						}
						fi.Date = f.PatchHeader.AuthorDate.String()
					}

					if outputOptions.Redact {
						fi.Redact()
					}

					if outputOptions.Verbose {
						printFinding(fi)
					}
					mu.Lock()
					findings = append(findings, fi)
					mu.Unlock()

				}
			}
		}(f)
	}

	wg.Wait()
	return findings
}
