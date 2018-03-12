package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const usage = `
usage: gitleaks [options] <URL>/<path_to_repo>

Options:
 -u --user 		Git user mode
 -r --repo 		Git repo mode
 -o --org 		Git organization mode
 -l --local 		Local mode, gitleaks will look for local repo in <path>
 -v --verbose 		Verbose mode, will output leaks as gitleaks finds them
 --report-path=<STR> 	Report output, default $GITLEAKS_HOME/report
 --clone-path=<STR>	Gitleaks will clone repos here, default $GITLEAKS_HOME/clones
 -t --temp 		Clone to temporary directory
 --concurrency=<INT> 	Upper bound on concurrent "git diff"
 --since=<STR> 		Commit to stop at
 --b64Entropy=<INT> 	Base64 entropy cutoff (default is 70)
 --hexEntropy=<INT>  	Hex entropy cutoff (default is 40)
 -e --entropy		Enable entropy		
 -h --help 		Display this message
 --token=<STR>    	Github API token
 --stopwords  		Enables stopwords

`

// Options for gitleaks
type Options struct {
	URL              string
	RepoPath         string
	ReportPath       string
	ClonePath        string
	Concurrency      int
	B64EntropyCutoff int
	HexEntropyCutoff int
	UserMode         bool
	OrgMode          bool
	RepoMode         bool
	LocalMode        bool
	Strict           bool
	Entropy          bool
	SinceCommit      string
	Tmp              bool
	Token            string
	Verbose          bool
	RegexFile        string
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
func newOpts(args []string) *Options {
	opts, err := defaultOptions()
	if err != nil {
		opts.failF("%v", err)
	}
	err = opts.parseOptions(args)
	if err != nil {
		opts.failF("%v", err)
	}
	return opts
}

// deafultOptions provides the default options used by newOpts
func defaultOptions() (*Options, error) {
	return &Options{
		Concurrency:      10,
		B64EntropyCutoff: 70,
		HexEntropyCutoff: 40,
	}, nil
}

// parseOptions will parse options supplied by the user.
func (opts *Options) parseOptions(args []string) error {
	if len(args) == 0 {
		opts.LocalMode = true
		opts.RepoPath, _ = os.Getwd()
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--stopwords":
			opts.Strict = true
		case "-e", "--entropy":
			opts.Entropy = true
		case "-o", "--org":
			opts.OrgMode = true
		case "-u", "--user":
			opts.UserMode = true
		case "-r", "--repo":
			opts.RepoMode = true
		case "-l", "--local":
			opts.LocalMode = true
		case "-v", "--verbose":
			opts.Verbose = true
		case "-t", "--temp":
			opts.Tmp = true
		case "-h", "--help":
			help()
			os.Exit(ExitClean)
		default:
			if match, value := opts.optString(arg, "--token="); match {
				opts.Token = value
			} else if match, value := opts.optString(arg, "--since="); match {
				opts.SinceCommit = value
			} else if match, value := opts.optString(arg, "--report-path="); match {
				opts.ReportPath = value
			} else if match, value := opts.optString(arg, "--clone-path="); match {
				opts.ClonePath = value
			} else if match, value := opts.optInt(arg, "--b64Entropy="); match {
				opts.B64EntropyCutoff = value
			} else if match, value := opts.optInt(arg, "--hexEntropy="); match {
				opts.HexEntropyCutoff = value
			} else if match, value := opts.optInt(arg, "--concurrency="); match {
				opts.Concurrency = value
			} else if match, value := opts.optString(arg, "--regex-file="); match {
				opts.RegexFile = value
			} else if i == len(args)-1 {
				if opts.LocalMode {
					opts.RepoPath = filepath.Clean(args[i])
				} else {
					if isGithubTarget(args[i]) {
						opts.URL = args[i]
					} else {
						help()
						return fmt.Errorf("Unknown option %s\n", arg)
					}
				}
			} else {
				help()
				return fmt.Errorf("Unknown option %s\n", arg)
			}
		}
	}

	if opts.RegexFile != "" {
		err := opts.loadExternalRegex()
		if err != nil {
			return fmt.Errorf("unable to load regex from file %s: %v",
				opts.RegexFile, err)
		}
	}

	if !opts.RepoMode && !opts.UserMode && !opts.OrgMode && !opts.LocalMode {
		if opts.URL != "" {
			opts.RepoMode = true
			err := opts.guards()
			if err != nil {
				return err
			}
			return nil
		}

		pwd, _ = os.Getwd()
		// check if pwd contains a .git, if it does, run local mode
		dotGitPath := filepath.Join(pwd, ".git")

		if _, err := os.Stat(dotGitPath); os.IsNotExist(err) {
			return fmt.Errorf("gitleaks has no target: %v", err)
		} else {
			opts.LocalMode = true
			opts.RepoPath = pwd
			opts.RepoMode = false
		}
	}

	err := opts.guards()
	if err != nil {
		return err
	}
	return err
}

// loadExternalRegex loads regexes from a text file if available.
func (opts *Options) loadExternalRegex() error {
	file, err := os.Open(opts.RegexFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		externalRegex = append(externalRegex, regexp.MustCompile(scanner.Text()))
	}

	return nil
}

// failF prints a failure message out to stderr, displays help
// and exits with a exit code 2
func (opts *Options) failF(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	help()
	os.Exit(ExitFailure)
}

// guards will prevent gitleaks from continuing if any invalid options
// are found.
func (opts *Options) guards() error {
	if (opts.RepoMode || opts.OrgMode || opts.UserMode) && opts.LocalMode {
		return fmt.Errorf("Cannot run Gitleaks on repo/user/org mode and local mode\n")
	} else if (opts.RepoMode || opts.OrgMode || opts.UserMode) && !isGithubTarget(opts.URL) {
		return fmt.Errorf("Not valid github target %s\n", opts.URL)
	} else if (opts.RepoMode || opts.UserMode) && opts.OrgMode {
		return fmt.Errorf("Cannot run Gitleaks on more than one mode\n")
	} else if (opts.OrgMode || opts.UserMode) && opts.RepoMode {
		return fmt.Errorf("Cannot run Gitleaks on more than one mode\n")
	} else if (opts.OrgMode || opts.RepoMode) && opts.UserMode {
		return fmt.Errorf("Cannot run Gitleaks on more than one mode\n")
	} else if opts.LocalMode && opts.Tmp {
		return fmt.Errorf("Cannot run Gitleaks with temp settings and local mode\n")
	} else if opts.SinceCommit != "" && (opts.OrgMode || opts.UserMode) {
		return fmt.Errorf("Cannot run Gitleaks with since commit flag and a owner mode\n")
	} else if opts.ClonePath != "" && opts.Tmp {
		return fmt.Errorf("Cannot run Gitleaks with --clone-path set and temporary repo\n")
	}
	return nil
}

// isGithubTarget checks if url is a valid github target
func isGithubTarget(url string) bool {
	re := regexp.MustCompile("github.com")
	return re.MatchString(url)
}
