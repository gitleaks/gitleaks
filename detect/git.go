package detect

import (
	"sync"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	godocutil "golang.org/x/tools/godoc/util"
)

// FromGit accepts a gitdiff.File channel (structure output from `git log -p`) and a configuration
// struct. Files from the gitdiff.File channel are then checked against each rule in the configuration to
// check for secrets. If any secrets are found, they are added to the list of findings.
func FromGit(files <-chan *gitdiff.File, cfg config.Config, outputOptions Options) []*report.Finding {
	var findings []*report.Finding
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

			commitSHA := ""

			// Check if commit is allowed
			if f.PatchHeader != nil {
				commitSHA = f.PatchHeader.SHA

				if cfg.Allowlist.CommitAllowed(f.PatchHeader.SHA) {
					return
				}
			}

			for _, tf := range f.TextFragments {
				if f.TextFragments == nil {
					// TODO fix this in gitleaks gitdiff fork
					// https://github.com/gitleaks/gitleaks/issues/11
					continue
				}

				if !godocutil.IsText([]byte(tf.Raw(gitdiff.OpAdd))) {
					continue
				}

				for _, fi := range DetectFindings(cfg, []byte(tf.Raw(gitdiff.OpAdd)), f.NewName, commitSHA) {
					fi.StartLine += int(tf.NewPosition)
					fi.EndLine += int(tf.NewPosition)
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
					findings = append(findings, &fi)
					mu.Unlock()

				}
			}
		}(f)
	}

	wg.Wait()
	return findings
}
