package manager

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/zricethezav/gitleaks/v5/config"
	"github.com/zricethezav/gitleaks/v5/options"

	"github.com/go-git/go-git/v5"
	"github.com/hako/durafmt"
	"github.com/mattn/go-colorable"
	log "github.com/sirupsen/logrus"
)

const maxLineLen = 200

// Manager is a struct containing options and configs as well CloneOptions and CloneDir.
// This struct is passed into each NewRepo so we are not passing around the manager in func params.
type Manager struct {
	Opts   options.Options
	Config config.Config

	CloneOptions *git.CloneOptions
	CloneDir     string

	leaks     []Leak
	leakChan  chan Leak
	leakWG    *sync.WaitGroup
	leakCache map[string]bool

	stopChan chan os.Signal
	metadata Metadata
	metaWG   *sync.WaitGroup
}

// Leak is a struct that contains information about some line of code that contains
// sensitive information as determined by the rules set in a gitleaks config
type Leak struct {
	Line       string    `json:"line"`
	LineNumber int       `json:"lineNumber"`
	Offender   string    `json:"offender"`
	Commit     string    `json:"commit"`
	Repo       string    `json:"repo"`
	Rule       string    `json:"rule"`
	Message    string    `json:"commitMessage"`
	Author     string    `json:"author"`
	Email      string    `json:"email"`
	File       string    `json:"file"`
	Date       time.Time `json:"date"`
	Tags       string    `json:"tags"`
	Operation  string    `json:"operation"`
	lookupHash string
}

// ScanTime is a type used to determine total scan time
type ScanTime int64

// PatchTime is a type used to determine total patch time during an scan
type PatchTime int64

// CloneTime is a type used to determine total clone time
type CloneTime int64

// RegexTime is a type used to determine the time each rules' regex takes. This is especially useful
// if you notice that gitleaks is taking a long time. You can use --debug to see the output of the regexTime
// so you can determine which regex is not performing well.
type RegexTime struct {
	Time  int64
	Regex string
}

// Metadata is a struct used to communicate metadata about an scan like timings and total commit counts.
type Metadata struct {
	mux  *sync.Mutex
	data map[string]interface{}

	timings chan interface{}

	RegexTime map[string]int64
	Commits   int
	ScanTime  int64
	patchTime int64
	cloneTime int64
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	// Fix colors on Windows
	if runtime.GOOS == "windows" {
		log.SetOutput(colorable.NewColorableStdout())
	}
}

// NewManager accepts options and returns a manager struct. The manager is a container for gitleaks configurations,
// options and channel receivers.
func NewManager(opts options.Options, cfg config.Config) (*Manager, error) {
	cloneOpts, err := opts.CloneOptions()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		Opts:         opts,
		Config:       cfg,
		CloneOptions: cloneOpts,

		stopChan:  make(chan os.Signal, 1),
		leakChan:  make(chan Leak),
		leakWG:    &sync.WaitGroup{},
		leakCache: make(map[string]bool),
		metaWG:    &sync.WaitGroup{},
		metadata: Metadata{
			RegexTime: make(map[string]int64),
			timings:   make(chan interface{}),
			data:      make(map[string]interface{}),
			mux:       new(sync.Mutex),
		},
	}

	signal.Notify(m.stopChan, os.Interrupt)

	// start receiving leaks and metadata
	go m.receiveLeaks()
	go m.receiveMetadata()
	go m.receiveInterrupt()

	return m, nil
}

// GetLeaks returns all available leaks
func (manager *Manager) GetLeaks() []Leak {
	// need to wait for any straggling leaks
	manager.leakWG.Wait()
	return manager.leaks
}

// SendLeaks accepts a leak and is used by the scan pkg. This is the public function
// that allows other packages to send leaks to the manager.
func (manager *Manager) SendLeaks(l Leak) {
	if len(l.Line) > maxLineLen {
		l.Line = l.Line[0:maxLineLen-1] + "..."
	}
	if len(l.Offender) > maxLineLen {
		l.Offender = l.Offender[0:maxLineLen-1] + "..."
	}
	h := sha1.New()
	h.Write([]byte(l.Commit + l.Offender + l.File + l.Line + string(l.LineNumber)))
	l.lookupHash = hex.EncodeToString(h.Sum(nil))
	if manager.Opts.Redact {
		l.Line = strings.ReplaceAll(l.Line, l.Offender, "REDACTED")
		l.Offender = "REDACTED"
	}
	manager.leakWG.Add(1)
	manager.leakChan <- l
}

func (manager *Manager) alreadySeen(leak Leak) bool {
	if _, ok := manager.leakCache[leak.lookupHash]; ok {
		return true
	}
	manager.leakCache[leak.lookupHash] = true
	return false
}

// receiveLeaks listens to leakChan for incoming leaks. If any are received, they are appended to the
// manager's leaks for future reporting. If the -v/--verbose option is set the leaks will marshaled into
// json and printed out.
func (manager *Manager) receiveLeaks() {
	for leak := range manager.leakChan {
		if manager.alreadySeen(leak) {
			manager.leakWG.Done()
			continue
		}
		manager.leaks = append(manager.leaks, leak)
		if manager.Opts.Verbose {
			var b []byte
			if manager.Opts.PrettyPrint {
				b, _ = json.MarshalIndent(leak, "", "	")
			} else {
				b, _ = json.Marshal(leak)
			}
			fmt.Println(string(b))
		}
		manager.leakWG.Done()
	}
}

// GetMetadata returns the metadata. TODO this may not need to be private
func (manager *Manager) GetMetadata() Metadata {
	manager.metaWG.Wait()
	return manager.metadata
}

// receiveMetadata is where the messages sent to the metadata channel get consumed. You can view metadata
// by running gitleaks with the --debug option set. This is extremely useful when trying to optimize regular
// expressions as that what gitleaks spends most of its cycles on.
func (manager *Manager) receiveMetadata() {
	for t := range manager.metadata.timings {
		switch ti := t.(type) {
		case CloneTime:
			manager.metadata.cloneTime += int64(ti)
		case ScanTime:
			manager.metadata.ScanTime += int64(ti)
		case PatchTime:
			manager.metadata.patchTime += int64(ti)
		case RegexTime:
			manager.metadata.RegexTime[ti.Regex] = manager.metadata.RegexTime[ti.Regex] + ti.Time
		}
		manager.metaWG.Done()
	}
}

// IncrementCommits increments total commits during an scan by i.
func (manager *Manager) IncrementCommits(i int) {
	manager.metadata.mux.Lock()
	manager.metadata.Commits += i
	manager.metadata.mux.Unlock()
}

// RecordTime accepts an interface and sends it to the manager's time channel
func (manager *Manager) RecordTime(t interface{}) {
	manager.metaWG.Add(1)
	manager.metadata.timings <- t
}

// DebugOutput logs metadata and other messages that occurred during a gitleaks scan
func (manager *Manager) DebugOutput() {
	log.Debugf("-------------------------\n")
	log.Debugf("| Times and Commit Counts|\n")
	log.Debugf("-------------------------\n")
	fmt.Println("totalScanTime: ", durafmt.Parse(time.Duration(manager.metadata.ScanTime)*time.Nanosecond))
	fmt.Println("totalPatchTime: ", durafmt.Parse(time.Duration(manager.metadata.patchTime)*time.Nanosecond))
	fmt.Println("totalCloneTime: ", durafmt.Parse(time.Duration(manager.metadata.cloneTime)*time.Nanosecond))
	fmt.Println("totalCommits: ", manager.metadata.Commits)

	const padding = 6
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, '.', 0)

	log.Debugf("--------------------------\n")
	log.Debugf("| Individual Regex Times |\n")
	log.Debugf("--------------------------\n")
	for k, v := range manager.metadata.RegexTime {
		_, _ = fmt.Fprintf(w, "%s\t%s\n", k, durafmt.Parse(time.Duration(v)*time.Nanosecond))
	}
	_ = w.Flush()

}

// Report saves gitleaks leaks to a json specified by --report={report.json}
func (manager *Manager) Report() error {
	close(manager.leakChan)
	close(manager.metadata.timings)

	if log.IsLevelEnabled(log.DebugLevel) {
		manager.DebugOutput()
	}

	if manager.Opts.Report != "" {
		if len(manager.GetLeaks()) == 0 {
			log.Infof("no leaks found, skipping writing report")
			return nil
		}
		file, err := os.Create(manager.Opts.Report)
		if err != nil {
			return err
		}

		if manager.Opts.ReportFormat == "json" {
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", " ")
			err = encoder.Encode(manager.leaks)
			if err != nil {
				return err
			}
		} else {
			w := csv.NewWriter(file)
			_ = w.Write([]string{"repo", "line", "commit", "offender", "rule", "tags", "commitMsg", "author", "email", "file", "date"})
			for _, leak := range manager.GetLeaks() {
				w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Rule, leak.Tags, leak.Message, leak.Author, leak.Email, leak.File, leak.Date.Format(time.RFC3339)})
			}
			w.Flush()
		}
		_ = file.Close()

		log.Infof("report written to %s", manager.Opts.Report)
	}
	return nil
}

func (manager *Manager) receiveInterrupt() {
	<-manager.stopChan
	if manager.Opts.Report != "" {
		err := manager.Report()
		if err != nil {
			log.Error(err)
		}
	}
	log.Info("gitleaks received interrupt, stopping scan")
	os.Exit(options.ErrorEncountered)
}
