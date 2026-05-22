package version

//
// IMPORTANT: DefaultMsg and Version must be set to the same value!
//

// DefaultMsg is the same as Version but used to check if Version was replaced
// during a build
var DefaultMsg = "version is set by build process"

// Version is the version of the tool set during the build
var Version = "version is set by build process"
