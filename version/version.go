package version

// DefaultMsg and Version must stay in sync; both are overridden by the build
// process via -ldflags.
var DefaultMsg = "version is set by build process"
var Version = "version is set by build process"
