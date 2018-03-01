package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"regexp"
	"github.com/mitchellh/go-homedir"
	"path/filepath"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const DEBUG = 0
const INFO = 1
const ERROR = 2

const usage = `usage: gitleaks [options] <URL>/<path_to_repo>

Options:
Modes
 -u --user 		Git user mode
 -r --repo 		Git repo mode
 -o --org 		Git organization mode
 -l --local 		Local mode, gitleaks will look for local repo in <path>

Logging
 -ll <INT> --log=<INT> 	0: Debug, 1: Info, 3: Error
 -v --verbose 		Verbose mode, will output leaks as gitleaks finds them

Locations
 --report_path=<STR> 	Report output, default $GITLEAKS_HOME/report
 --clone_path=<STR>	Gitleaks will clone repos here, default $GITLEAKS_HOME/clones

Other
 -t --temp 		Clone to temporary directory
 -c <INT> 		Upper bound on concurrent diffs
 --since=<STR> 		Commit to stop at
 --b64Entropy=<INT> 	Base64 entropy cutoff (default is 70)
 --hexEntropy=<INT>  	Hex entropy cutoff (default is 40)
 -e --entropy		Enable entropy		
 -h --help 		Display this message
 --token=<STR>    	Github API token
 --stopwords  		Enables stopwords

`


// Options for gitleaks. need to support remote repo/owner
// and local repo/owner mode
type Options struct {
	URL 			 string
	RepoPath 	     string

	ClonePath 		 string
	ReportPath 	     string

	Concurrency      int
	B64EntropyCutoff int
	HexEntropyCutoff int

	// MODES
	UserMode         bool
	OrgMode          bool
	RepoMode       	 bool
	LocalMode 		 bool

	// OPTS
	Strict           bool
	Entropy          bool
	SinceCommit      string
	Persist          bool
	IncludeForks     bool
	Tmp              bool
	ReportOut 		 bool
	Token            string

	// LOGS/REPORT
	Verbose          bool
	LogLevel 		 int
}

// help prints the usage string and exits
func help() {
	os.Stderr.WriteString(usage)
}

// optionsNextInt is a parseOptions helper that returns the value (int) of an option if valid
func (opts *Options) nextInt(args []string, i *int) int {
	if len(args) > *i+1 {
		*i++
	} else {
		help()
	}
	argInt, err := strconv.Atoi(args[*i])
	if err != nil {
		opts.failF("Invalid %s option: %s\n", args[*i-1], args[*i])
	}
	return argInt
}

// optionsNextString is a parseOptions helper that returns the value (string) of an option if valid
func (opts *Options) nextString(args []string, i *int) string {
	if len(args) > *i+1 {
		*i++
	} else {
		opts.failF("Invalid %s option: %s\n", args[*i-1], args[*i])
	}
	return args[*i]
}

// optInt grabs the string ...
func (opts *Options) optString(arg string, prefixes ...string) (bool, string) {
	for _, prefix := range prefixes {
		if strings.HasPrefix(arg, prefix) {
			return true, arg[len(prefix):]
		}
	}
	return false, ""
}

// optInt grabs the int ...
func (opts *Options) optInt(arg string, prefixes ...string) (bool, int) {
	for _, prefix := range prefixes {
		if strings.HasPrefix(arg, prefix) {
			i, err := strconv.Atoi(arg[len(prefix):])
			if err != nil {
				opts.failF("Invalid %s int option\n", prefix)
			}
			return true, i
		}
	}
	return false, 0
}

// newOpts generates opts and parses arguments
func newOpts(args []string) (*Options) {
	opts, err := defaultOptions()
	if err != nil{
		opts.failF("%v", err)
	}
	err = opts.parseOptions(args)
	if err != nil{
		opts.failF("%v", err)
	}
	opts.setupLogger()
	return opts
}

// deafultOptions provides the default options
func defaultOptions() (*Options, error) {
	// default GITLEAKS_HOME is $HOME/.gitleaks
	// gitleaks will use this location for clones if
	// no clone-path is provided
	gitleaksHome := os.Getenv("GITLEAKS_HOME")
	if gitleaksHome == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("could not find system home dir")
		}
		gitleaksHome = filepath.Join(homeDir, ".gitleaks")
	}

	// make sure gitleaks home exists
	if _, err := os.Stat(gitleaksHome); os.IsNotExist(err) {
		os.Mkdir(gitleaksHome, os.ModePerm)
	}

	return &Options{
		Concurrency:      10,
		B64EntropyCutoff: 70,
		HexEntropyCutoff: 40,
		LogLevel: INFO,
		ClonePath: filepath.Join(gitleaksHome, "clone"),
		ReportPath: filepath.Join(gitleaksHome, "report"),
	}, nil
}

// parseOptions
func (opts *Options) parseOptions(args []string) error {

	if len(args) == 0 {
		help()
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-s":
			opts.SinceCommit = opts.nextString(args, &i)
		case "--strict":
			opts.Strict = true
		case "-b", "--b64Entropy":
			opts.B64EntropyCutoff = opts.nextInt(args, &i)
		case "-x", "--hexEntropy":
			opts.HexEntropyCutoff = opts.nextInt(args, &i)
		case "-e", "--entropy":
			opts.Entropy = true
		case "-c":
			opts.Concurrency = opts.nextInt(args, &i)

		case "-o", "--org":
			opts.OrgMode = true
		case "-u", "--user":
			opts.UserMode = true
		case "-r", "--repo":
			opts.RepoMode = true
		case "-l", "--local":
			opts.LocalMode = true

		case "--report-out":
			opts.ReportOut = true

		case "-t", "--temp":
			opts.Tmp = true
		case "-ll":
			opts.LogLevel = opts.nextInt(args, &i)
		case "-h", "--help":
			help()
			os.Exit(EXIT_CLEAN)
		default:
			// TARGETS
			if i == len(args)-1 {
				fmt.Println(arg[i])
				if opts.LocalMode {
					opts.RepoPath = args[i]
				} else {
					opts.URL = args[i]
				}
			} else if match, value := opts.optString(arg, "--token="); match {
				opts.Token = value
			} else if match, value := opts.optString(arg, "--since="); match {
				opts.SinceCommit = value
			} else if match, value := opts.optString(arg, "--report-path="); match {
				opts.ReportPath = value
			} else if match, value := opts.optString(arg, "--clone-path="); match {
				opts.ClonePath = value
			} else if match, value := opts.optInt(arg, "--log="); match {
				opts.LogLevel = value
			} else if match, value := opts.optInt(arg, "--b64Entropy="); match {
				opts.B64EntropyCutoff = value
			} else if match, value := opts.optInt(arg, "--hexEntropy="); match {
				opts.HexEntropyCutoff = value
			} else {
				fmt.Printf("Unknown option %s\n\n", arg)
				help()
				return fmt.Errorf("Unknown option %s\n\n", arg)
			}
		}
	}
	err := opts.guards()
	if err != nil{
		fmt.Printf("%v", err)
	}
	return err
}

// failF prints a failure message out to stderr, displays help
// and exits with a exit code 2
func (opts *Options) failF(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	help()
	os.Exit(EXIT_FAILURE)
}

// guards will prevent gitleaks from continuing if any invalid options
// are found.
func (opts *Options) guards() error {
	if (opts.RepoMode || opts.OrgMode || opts.UserMode) && !isGithubTarget(opts.URL) {
		return fmt.Errorf("Not valid github target %s\n", opts.URL)
	} else if (opts.RepoMode || opts.OrgMode || opts.UserMode) && opts.LocalMode {
		return fmt.Errorf("Cannot run Gitleaks on repo/user/org mode and local mode\n")
	} else if (opts.RepoMode || opts.UserMode) && opts.OrgMode {
		return fmt.Errorf("Cannot run Gitleaks on more than one mode\n")
	} else if (opts.OrgMode || opts.UserMode) && opts.RepoMode {
		return fmt.Errorf("Cannot run Gitleaks on more than one mode\n")
	} else if (opts.OrgMode || opts.RepoMode) && opts.UserMode{
		return fmt.Errorf("Cannot run Gitleaks on more than one mode\n")
	} else if opts.LocalMode && opts.Tmp {
		return fmt.Errorf("Cannot run Gitleaks with temp settings and local mode\n")
	} else if opts.SinceCommit != "" && (opts.OrgMode || opts.UserMode) {
		return fmt.Errorf("Cannot run Gitleaks with since commit flag and a owner mode\n")
	}

	return nil
}

// setupLogger initiates the logger and sets the logging level
// based on what is set in arguments. Default logging level is
// INFO
func (opts *Options) setupLogger() {
	atom := zap.NewAtomicLevel()
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = ""
	logger = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		atom,
	))

	switch opts.LogLevel {
	case DEBUG:
		atom.SetLevel(zap.DebugLevel)
	case INFO:
		atom.SetLevel(zap.InfoLevel)
	case ERROR:
		atom.SetLevel(zap.ErrorLevel)
	}
}

// isGithubTarget checks if url is a valid github target
func isGithubTarget(url string) bool {
	re := regexp.MustCompile("github\\.com\\/")
	return re.MatchString(url)
}
