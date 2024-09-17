package detect

import (
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func (d *Detector) DetectGit(gitCmd *sources.GitCmd) ([]report.Finding, error) {
	defer gitCmd.Wait()
	diffFilesCh := gitCmd.DiffFilesCh()
	errCh := gitCmd.ErrCh()

	// loop to range over both DiffFiles (stdout) and ErrCh (stderr)
	for diffFilesCh != nil || errCh != nil {
		select {
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
				break
			}

			// skip binary files
			if gitdiffFile.IsBinary || gitdiffFile.IsDelete {
				continue
			}

			// Check if commit is allowed
			commitSHA := ""
			if gitdiffFile.PatchHeader != nil {
				commitSHA = gitdiffFile.PatchHeader.SHA
				if d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA) {
					continue
				}
			}
			d.addCommit(commitSHA)

			d.Sema.Go(func() error {
				for _, textFragment := range gitdiffFile.TextFragments {
					if textFragment == nil {
						return nil
					}

					fragment := Fragment{
						Raw:       textFragment.Raw(gitdiff.OpAdd),
						CommitSHA: commitSHA,
						FilePath:  gitdiffFile.NewName,
					}

					for _, finding := range d.Detect(fragment) {
						d.addFinding(augmentGitFinding(finding, textFragment, gitdiffFile))
					}
				}
				return nil
			})
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			return d.findings, err
		}
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}
	log.Info().Msgf("%d commits scanned.", len(d.commitMap))
	log.Debug().Msg("Note: this number might be smaller than expected due to commits with no additions")
	return d.findings, nil
}
