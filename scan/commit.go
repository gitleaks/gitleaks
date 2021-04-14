package scan

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/go-git/go-git/v5"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// CommitScanner is a commit scanner
type CommitScanner struct {
	cfg      config.Config
	opts     options.Options
	repo     *git.Repository
	repoName string
	commit   *object.Commit
}

// NewCommitScanner creates and returns a commit scanner
func NewCommitScanner(opts options.Options, cfg config.Config, repo *git.Repository, commit *object.Commit) *CommitScanner {
	cs := &CommitScanner{
		cfg:      cfg,
		opts:     opts,
		repo:     repo,
		commit:   commit,
		repoName: getRepoName(opts),
	}
	return cs
}

// SetRepoName sets the repo name of the scanner.
func (cs *CommitScanner) SetRepoName(repoName string) {
	cs.repoName = repoName
}

// Scan kicks off a CommitScanner Scan
func (cs *CommitScanner) Scan() (Report, error) {
	var scannerReport Report

	defer func() {
		if err := recover(); err != nil {
			// sometimes the Patch generation will fail due to a known bug in
			// sergi's go-diff: https://github.com/sergi/go-diff/issues/89.
			return
		}
	}()

	if cs.cfg.Allowlist.CommitAllowed(cs.commit.Hash.String()) {
		return scannerReport, nil
	}

	if len(cs.commit.ParentHashes) == 0 {
		facScanner := NewFilesAtCommitScanner(cs.opts, cs.cfg, cs.repo, cs.commit)
		return facScanner.Scan()
	}

	parent, err := cs.commit.Parent(0)
	if err != nil {
		return scannerReport, err
	}

	if parent == nil {
		return scannerReport, nil
	}

	patch, err := parent.Patch(cs.commit)
	if err != nil || patch == nil {
		return scannerReport, fmt.Errorf("could not generate Patch")
	}

	patchContent := patch.String()

	for _, f := range patch.FilePatches() {
		if f.IsBinary() {
			continue
		}
		for _, chunk := range f.Chunks() {
			if chunk.Type() == fdiff.Add {
				_, to := f.Files()
				if cs.cfg.Allowlist.FileAllowed(filepath.Base(to.Path())) ||
					cs.cfg.Allowlist.PathAllowed(to.Path()) {
					continue
				}

				// Check individual file path ONLY rules
				for _, rule := range cs.cfg.Rules {
					if rule.CommitAllowed(cs.commit.Hash.String()) {
						continue
					}

					if rule.HasFileOrPathLeakOnly(to.Path()) {
						leak := NewLeak("", "Filename or path offender: "+to.Path(), defaultLineNumber).WithCommit(cs.commit)
						leak.Repo = cs.repoName
						leak.File = to.Path()
						leak.RepoURL = cs.opts.RepoURL
						leak.LeakURL = leak.URL()
						leak.Rule = rule.Description
						leak.Tags = strings.Join(rule.Tags, ", ")

						leak.Log(cs.opts)

						scannerReport.Leaks = append(scannerReport.Leaks, leak)
						continue
					}
				}

				lineLookup := make(map[string]bool)

				// Check the actual content
				for _, line := range strings.Split(chunk.Content(), "\n") {
					for _, rule := range cs.cfg.Rules {
						if rule.AllowList.FileAllowed(filepath.Base(to.Path())) ||
							rule.AllowList.PathAllowed(to.Path()) ||
							rule.AllowList.CommitAllowed(cs.commit.Hash.String()) {
							continue
						}
						offender := rule.Inspect(line)
						if offender.IsEmpty() {
							continue
						}

						if cs.cfg.Allowlist.RegexAllowed(line) {
							continue
						}

						if rule.File.String() != "" && !rule.HasFileLeak(filepath.Base(to.Path())) {
							continue
						}
						if rule.Path.String() != "" && !rule.HasFilePathLeak(to.Path()) {
							continue
						}

						leak := NewLeak(line, offender.ToString(), defaultLineNumber).WithCommit(cs.commit).WithEntropy(offender.EntropyLevel)
						leak.File = to.Path()
						leak.LineNumber = extractLine(patchContent, leak, lineLookup)
						leak.RepoURL = cs.opts.RepoURL
						leak.Repo = cs.repoName
						leak.LeakURL = leak.URL()
						leak.Rule = rule.Description
						leak.Tags = strings.Join(rule.Tags, ", ")

						leak.Log(cs.opts)

						scannerReport.Leaks = append(scannerReport.Leaks, leak)
					}
				}
			}
		}
	}
	scannerReport.Commits = 1
	return scannerReport, nil
}
