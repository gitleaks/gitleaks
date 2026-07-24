package sdk

import (
	"context"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Option mutates scanner behavior.
type Option func(*Scanner)

// Scanner wraps gitleaks detector orchestration for embedding use-cases.
type Scanner struct {
	config            config.Config
	redact            uint
	maxDecodeDepth    int
	maxArchiveDepth   int
	maxTargetMegaByte int
	followSymlinks    bool
	ignoreAllow       bool
	ignoreFiles       []string
}

// ScanResult bundles raw findings with the computed vector state.
type ScanResult struct {
	Findings []report.Finding
	State    VectorState
}

// NewScanner creates a reusable scanner with immutable config and options.
func NewScanner(cfg config.Config, opts ...Option) *Scanner {
	s := &Scanner{config: cfg}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithRedact(level uint) Option {
	return func(s *Scanner) { s.redact = level }
}

func WithMaxDecodeDepth(depth int) Option {
	return func(s *Scanner) { s.maxDecodeDepth = depth }
}

func WithMaxArchiveDepth(depth int) Option {
	return func(s *Scanner) { s.maxArchiveDepth = depth }
}

func WithMaxTargetMegaBytes(limit int) Option {
	return func(s *Scanner) { s.maxTargetMegaByte = limit }
}

func WithFollowSymlinks(enabled bool) Option {
	return func(s *Scanner) { s.followSymlinks = enabled }
}

func WithIgnoreGitleaksAllow(enabled bool) Option {
	return func(s *Scanner) { s.ignoreAllow = enabled }
}

func WithGitleaksIgnorePath(path string) Option {
	return func(s *Scanner) { s.ignoreFiles = append(s.ignoreFiles, path) }
}

// ScanString scans a string payload and returns findings.
func (s *Scanner) ScanString(content string) ([]report.Finding, error) {
	d, err := s.newDetector(context.Background())
	if err != nil {
		return nil, err
	}
	return d.DetectString(content), nil
}

// ScanStringWithState scans a string payload and computes vector state.
func (s *Scanner) ScanStringWithState(content string, exemptions *ExemptionManager) (ScanResult, error) {
	findings, err := s.ScanString(content)
	if err != nil {
		return ScanResult{}, err
	}
	return scanResult(findings, exemptions), nil
}

// ScanBytes scans bytes and returns findings.
func (s *Scanner) ScanBytes(content []byte) ([]report.Finding, error) {
	d, err := s.newDetector(context.Background())
	if err != nil {
		return nil, err
	}
	return d.DetectBytes(content), nil
}

// ScanBytesWithState scans bytes and computes vector state.
func (s *Scanner) ScanBytesWithState(content []byte, exemptions *ExemptionManager) (ScanResult, error) {
	findings, err := s.ScanBytes(content)
	if err != nil {
		return ScanResult{}, err
	}
	return scanResult(findings, exemptions), nil
}

// ScanPath scans files under the provided path.
func (s *Scanner) ScanPath(ctx context.Context, path string) ([]report.Finding, error) {
	d, err := s.newDetector(ctx)
	if err != nil {
		return nil, err
	}

	files := &sources.Files{
		Config:          &d.Config,
		FollowSymlinks:  d.FollowSymlinks,
		MaxFileSize:     d.MaxTargetMegaBytes * 1_000_000,
		Path:            path,
		Sema:            d.Sema,
		MaxArchiveDepth: d.MaxArchiveDepth,
	}

	return d.DetectSource(ctx, files)
}

// ScanPathWithState scans files under path and computes vector state.
func (s *Scanner) ScanPathWithState(ctx context.Context, path string, exemptions *ExemptionManager) (ScanResult, error) {
	findings, err := s.ScanPath(ctx, path)
	if err != nil {
		return ScanResult{}, err
	}
	return scanResult(findings, exemptions), nil
}

// ScanGit scans git history using optional git log flags.
func (s *Scanner) ScanGit(ctx context.Context, repoPath string, logOpts string) ([]report.Finding, error) {
	d, err := s.newDetector(ctx)
	if err != nil {
		return nil, err
	}

	cmd, err := sources.NewGitLogCmdContext(ctx, repoPath, logOpts)
	if err != nil {
		return nil, err
	}

	gitSource := &sources.Git{
		Cmd:             cmd,
		Config:          &d.Config,
		Sema:            d.Sema,
		MaxArchiveDepth: d.MaxArchiveDepth,
	}
	return d.DetectSource(ctx, gitSource)
}

// ScanGitWithState scans git history and computes vector state.
func (s *Scanner) ScanGitWithState(ctx context.Context, repoPath string, logOpts string, exemptions *ExemptionManager) (ScanResult, error) {
	findings, err := s.ScanGit(ctx, repoPath, logOpts)
	if err != nil {
		return ScanResult{}, err
	}
	return scanResult(findings, exemptions), nil
}

// ScanGitStaged scans the staged git diff in a repository.
func (s *Scanner) ScanGitStaged(ctx context.Context, repoPath string) ([]report.Finding, error) {
	d, err := s.newDetector(ctx)
	if err != nil {
		return nil, err
	}

	cmd, err := sources.NewGitDiffCmdContext(ctx, repoPath, true)
	if err != nil {
		return nil, err
	}

	gitSource := &sources.Git{
		Cmd:             cmd,
		Config:          &d.Config,
		Sema:            d.Sema,
		MaxArchiveDepth: d.MaxArchiveDepth,
	}
	return d.DetectSource(ctx, gitSource)
}

// ScanGitStagedWithState scans staged git diff and computes vector state.
func (s *Scanner) ScanGitStagedWithState(ctx context.Context, repoPath string, exemptions *ExemptionManager) (ScanResult, error) {
	findings, err := s.ScanGitStaged(ctx, repoPath)
	if err != nil {
		return ScanResult{}, err
	}
	return scanResult(findings, exemptions), nil
}

func scanResult(findings []report.Finding, exemptions *ExemptionManager) ScanResult {
	return ScanResult{
		Findings: findings,
		State:    EvaluateVectorState(findings, exemptions),
	}
}

func (s *Scanner) newDetector(ctx context.Context) (*detect.Detector, error) {
	d := detect.NewDetectorContext(ctx, s.config)
	d.Redact = s.redact
	d.MaxDecodeDepth = s.maxDecodeDepth
	d.MaxArchiveDepth = s.maxArchiveDepth
	d.MaxTargetMegaBytes = s.maxTargetMegaByte
	d.FollowSymlinks = s.followSymlinks
	d.IgnoreGitleaksAllow = s.ignoreAllow

	for _, ignorePath := range s.ignoreFiles {
		if err := d.AddGitleaksIgnore(ignorePath); err != nil {
			return nil, err
		}
	}

	return d, nil
}
