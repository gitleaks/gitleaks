package flags

import "sync/atomic"

// https://github.com/gitleaks/gitleaks/pull/1731
var EnableExperimentalAllowlistOptimizations atomic.Bool
