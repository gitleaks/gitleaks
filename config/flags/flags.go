package flags

import "sync/atomic"

// https://github.com/gitleaks/gitleaks/pull/1500
var EnableExperimentalPatternChecks atomic.Bool
