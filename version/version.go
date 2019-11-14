package version

// Version is loaded via  LDFLAGS:
// VERSION := `git fetch --tags && git tag | sort -V | tail -1`
// LDFLAGS=-ldflags "-X=github.com/zricethezav/gitleaks-ng/version.Version=$(VERSION)"
var Version string
