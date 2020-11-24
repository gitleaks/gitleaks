package scan

import (
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// scan accepts a Patch, Commit, and repo. If the patches contains files that are
// binary, then gitleaks will skip scanning that file OR if a file is matched on
// allowlisted files set in the configuration. If a global rule for files is defined and a filename
// matches said global rule, then a leak is sent to the manager.
// After that, file chunks are created which are then inspected by InspectString()
func scanPatch(patch *object.Patch, c *object.Commit, repo *Repo) {
	bundle := Source{
		Commit:   c,
		Patch:    patch.String(),
		scanType: patchScan,
	}
	for _, f := range patch.FilePatches() {
		if repo.timeoutReached() {
			return
		}
		if f.IsBinary() {
			continue
		}
		for _, chunk := range f.Chunks() {
			if chunk.Type() == fdiff.Add || (repo.Manager.Opts.Deletion && chunk.Type() == fdiff.Delete) {
				bundle.Content = chunk.Content()
				bundle.Operation = chunk.Type()

				// get filepath
				from, to := f.Files()
				if from != nil {
					bundle.FilePath = from.Path()
				} else if to != nil {
					bundle.FilePath = to.Path()
				} else {
					bundle.FilePath = "???"
				}
				repo.CheckRules(&bundle)
			}
		}
	}
}
