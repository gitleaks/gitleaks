package scan

import (
	"runtime"

	"github.com/zricethezav/gitleaks/v7/options"
)

const (
	singleThreadCommitBuffer          = 1
	multiThreadCommitBufferMultiplier = 10
)

// Throttle is a struct that limits the number of concurrent goroutines and sets the
// number of threads available for gitleaks to use via GOMAXPROCS.
type Throttle struct {
	throttle chan bool
}

// NewThrottle accepts some options and returns a throttle for scanners to use
func NewThrottle(opts options.Options) *Throttle {
	t := Throttle{}
	if opts.Threads <= 1 {
		runtime.GOMAXPROCS(1)
		t.throttle = make(chan bool, singleThreadCommitBuffer)
		return &t
	}

	runtime.GOMAXPROCS(opts.Threads)
	t.throttle = make(chan bool, multiThreadCommitBufferMultiplier*opts.Threads)
	return &t

}

// Limit blocks new goroutines from spinning up if throttle is at capacity
func (t *Throttle) Limit() {
	t.throttle <- true
}

// Release releases the hold on the throttle, allowing more goroutines to be spun up
func (t *Throttle) Release() {
	<-t.throttle
}
