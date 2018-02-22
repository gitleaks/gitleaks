// +build !windows,!norwfs

package dotgit

import (
	"os"

	"gopkg.in/src-d/go-billy.v4"
)

const openAndLockPackedRefsMode = os.O_RDWR

func (d *DotGit) rewritePackedRefsWhileLocked(
	tmp billy.File, pr billy.File) error {
	// On non-Windows platforms, we can have atomic rename.
	return d.fs.Rename(tmp.Name(), pr.Name())
}
