package goblin

import (
	"flag"
	"fmt"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"
)

type Done func(error ...interface{})

type Runnable interface {
	run(*G) bool
}

type Itable interface {
	run(*G) bool
	failed(string, []string)
}

func (g *G) Describe(name string, h func()) {
	d := &Describe{name: name, h: h, parent: g.parent}

	if d.parent != nil {
		d.parent.children = append(d.parent.children, Runnable(d))
	}

	g.parent = d

	h()

	g.parent = d.parent

	if g.parent == nil && d.hasTests {
		g.reporter.begin()
		if d.run(g) {
			g.t.Fail()
		}
		g.reporter.end()
	}
}
func (g *G) Timeout(time time.Duration) {
	g.timeout = time
	g.timer.Reset(time)
}

type Describe struct {
	name       string
	h          func()
	children   []Runnable
	befores    []func()
	afters     []func()
	afterEach  []func()
	beforeEach []func()
	hasTests   bool
	parent     *Describe
}

func (d *Describe) runBeforeEach() {
	if d.parent != nil {
		d.parent.runBeforeEach()
	}

	for _, b := range d.beforeEach {
		b()
	}
}

func (d *Describe) runAfterEach() {

	if d.parent != nil {
		d.parent.runAfterEach()
	}

	for _, a := range d.afterEach {
		a()
	}
}

func (d *Describe) run(g *G) bool {
	failed := false
	if d.hasTests {
		g.reporter.beginDescribe(d.name)

		for _, b := range d.befores {
			b()
		}

		for _, r := range d.children {
			if r.run(g) {
				failed = true
			}
		}

		for _, a := range d.afters {
			a()
		}

		g.reporter.endDescribe()
	}

	return failed
}

type Failure struct {
	stack    []string
	testName string
	message  string
}

type It struct {
	h        interface{}
	name     string
	parent   *Describe
	failure  *Failure
	reporter Reporter
	isAsync  bool
}

func (it *It) run(g *G) bool {
	g.currentIt = it

	if it.h == nil {
		g.reporter.itIsPending(it.name)
		return false
	}
	//TODO: should handle errors for beforeEach
	it.parent.runBeforeEach()

	runIt(g, it.h)

	it.parent.runAfterEach()

	failed := false
	if it.failure != nil {
		failed = true
	}

	if failed {
		g.reporter.itFailed(it.name)
		g.reporter.failure(it.failure)
	} else {
		g.reporter.itPassed(it.name)
	}
	return failed
}

func (it *It) failed(msg string, stack []string) {
	it.failure = &Failure{stack: stack, message: msg, testName: it.parent.name + " " + it.name}
}

type Xit struct {
	h        interface{}
	name     string
	parent   *Describe
	failure  *Failure
	reporter Reporter
	isAsync  bool
}

func (xit *Xit) run(g *G) bool {
	g.currentIt = xit

	g.reporter.itIsExcluded(xit.name)
	return false
}

func (xit *Xit) failed(msg string, stack []string) {
	xit.failure = nil
}

func parseFlags() {
	//Flag parsing
	flag.Parse()
	if *regexParam != "" {
		runRegex = regexp.MustCompile(*regexParam)
	} else {
		runRegex = nil
	}
}

var timeout = flag.Duration("goblin.timeout", 5*time.Second, "Sets default timeouts for all tests")
var isTty = flag.Bool("goblin.tty", true, "Sets the default output format (color / monochrome)")
var regexParam = flag.String("goblin.run", "", "Runs only tests which match the supplied regex")
var runRegex *regexp.Regexp

func Goblin(t *testing.T, arguments ...string) *G {
	if !flag.Parsed() {
		parseFlags()
	}
	g := &G{t: t, timeout: *timeout}
	var fancy TextFancier
	if *isTty {
		fancy = &TerminalFancier{}
	} else {
		fancy = &Monochrome{}
	}

	g.reporter = Reporter(&DetailedReporter{fancy: fancy})
	return g
}

func runIt(g *G, h interface{}) {
	defer timeTrack(time.Now(), g)
	g.mutex.Lock()
	g.timedOut = false
	g.mutex.Unlock()
	g.timer = time.NewTimer(g.timeout)
	g.shouldContinue = make(chan bool)
	if call, ok := h.(func()); ok {
		// the test is synchronous
		go func(c chan bool) { call(); c <- true }(g.shouldContinue)
	} else if call, ok := h.(func(Done)); ok {
		doneCalled := 0
		go func(c chan bool) {
			call(func(msg ...interface{}) {
				if len(msg) > 0 {
					g.Fail(msg)
				} else {
					doneCalled++
					if doneCalled > 1 {
						g.Fail("Done called multiple times")
					}
					c <- true
				}
			})
		}(g.shouldContinue)
	} else {
		panic("Not implemented.")
	}
	select {
	case <-g.shouldContinue:
	case <-g.timer.C:
		//Set to nil as it shouldn't continue
		g.shouldContinue = nil
		g.timedOut = true
		g.Fail("Test exceeded " + fmt.Sprintf("%s", g.timeout))
	}
	// Reset timeout value
	g.timeout = *timeout
}

type G struct {
	t              *testing.T
	parent         *Describe
	currentIt      Itable
	timeout        time.Duration
	reporter       Reporter
	timedOut       bool
	shouldContinue chan bool
	mutex          sync.Mutex
	timer          *time.Timer
}

func (g *G) SetReporter(r Reporter) {
	g.reporter = r
}

func (g *G) It(name string, h ...interface{}) {
	if matchesRegex(name) {
		it := &It{name: name, parent: g.parent, reporter: g.reporter}
		notifyParents(g.parent)
		if len(h) > 0 {
			it.h = h[0]
		}
		g.parent.children = append(g.parent.children, Runnable(it))
	}
}

func (g *G) Xit(name string, h ...interface{}) {
	if matchesRegex(name) {
		xit := &Xit{name: name, parent: g.parent, reporter: g.reporter}
		notifyParents(g.parent)
		if len(h) > 0 {
			xit.h = h[0]
		}
		g.parent.children = append(g.parent.children, Runnable(xit))
	}
}

func matchesRegex(value string) bool {
	if runRegex != nil {
		return runRegex.MatchString(value)
	}
	return true
}

func notifyParents(d *Describe) {
	d.hasTests = true
	if d.parent != nil {
		notifyParents(d.parent)
	}
}

func (g *G) Before(h func()) {
	g.parent.befores = append(g.parent.befores, h)
}

func (g *G) BeforeEach(h func()) {
	g.parent.beforeEach = append(g.parent.beforeEach, h)
}

func (g *G) After(h func()) {
	g.parent.afters = append(g.parent.afters, h)
}

func (g *G) AfterEach(h func()) {
	g.parent.afterEach = append(g.parent.afterEach, h)
}

func (g *G) Assert(src interface{}) *Assertion {
	return &Assertion{src: src, fail: g.Fail}
}

func timeTrack(start time.Time, g *G) {
	g.reporter.itTook(time.Since(start))
}

func (g *G) Fail(error interface{}) {
	//Skips 7 stacks due to the functions between the stack and the test
	stack := ResolveStack(7)
	message := fmt.Sprintf("%v", error)
	g.currentIt.failed(message, stack)
	if g.shouldContinue != nil {
		g.shouldContinue <- true
	}
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if !g.timedOut {
		//Stop test function execution
		runtime.Goexit()
	}

}
