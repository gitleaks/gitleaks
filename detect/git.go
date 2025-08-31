package detect

import (
	"context"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// RemoteInfo is an alias for sources.RemoteInfo for backwards compatibility
//
// Deprecated: This will be replaced with sources.RemoteInfo in v9
type RemoteInfo sources.RemoteInfo

// DetectGit runs detections against a GitCmd with its remote info
//
// Deprecated: Use sources.Git and detector.DetectSource instead
func (d *Detector) DetectGit(cmd *sources.GitCmd, remote *RemoteInfo) ([]report.Finding, error) {
	return d.DetectSource(
		context.Background(),
		&sources.Git{
			Cmd:             cmd,
			Config:          &d.Config,
			Remote:          (*sources.RemoteInfo)(remote),
			Sema:            d.Sema,
			MaxArchiveDepth: d.MaxArchiveDepth,
		},
	)
}

// Deprecated: use sources.NewRemoteInfo instead
func NewRemoteInfo(platform scm.Platform, source string) *RemoteInfo {
	return (*RemoteInfo)(sources.NewRemoteInfo(platform, source))
}
