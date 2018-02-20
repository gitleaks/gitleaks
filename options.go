package main

import (
	"fmt"
	"os"
	"strconv"
)

// TODO regex on type.. user/organization can be treated as the same:
// 	hittps://github.com/<user or org>
// 	hittps://github.com/<user or org>/repo
const usage = `usage: gitleaks [git link] [options]

Options:
	-c 			Concurrency factor (potential number of git files open)
	-u 		 	Git user url
	-r 			Git repo url
	-o 			Git organization url
	-s 			Strict mode uses stopwords in checks.go
	-e 			Base64 entropy cutoff, default is 70
	-x 			Hex entropy cutoff, default is 40
	-h --help 		Display this message
`

// Options for gitleaks
type Options struct {
	Concurrency      int
	B64EntropyCutoff int
	HexEntropyCutoff int
	UserURL          string
	OrgURL           string
	RepoURL          string
	Strict           bool
}

// help prints the usage string and exits
func help() {
	os.Stderr.WriteString(usage)
	os.Exit(1)
}

// optionsNextInt is a parseOptions helper that returns the value (int) of an option
// if valid.
func optionsNextInt(args []string, i *int) int {
	if len(args) > *i+1 {
		*i++
	} else {
		help()
	}
	argInt, err := strconv.Atoi(args[*i])
	if err != nil {
		fmt.Printf("Invalid %s option: %s\n", args[*i-1], args[*i])
		help()
	}
	return argInt
}

// optionsNextString is a parseOptions helper that returns the value (string) of an option
// if valid.
func optionsNextString(args []string, i *int) string {
	if len(args) > *i+1 {
		*i++
	} else {
		fmt.Printf("Invalid %s option: %s\n", args[*i-1], args[*i])
		help()
	}
	return args[*i]
}

// parseOptions
func parseOptions(args []string) *Options {
	opts := &Options{
		Concurrency:      10,
		B64EntropyCutoff: 70,
		HexEntropyCutoff: 40,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-s":
			opts.Strict = true
		case "-e":
			opts.B64EntropyCutoff = optionsNextInt(args, &i)
		case "-x":
			opts.HexEntropyCutoff = optionsNextInt(args, &i)
		case "-c":
			opts.Concurrency = optionsNextInt(args, &i)
		case "-o":
			opts.OrgURL = optionsNextString(args, &i)
		case "-u":
			opts.UserURL = optionsNextString(args, &i)
		case "-r":
			opts.RepoURL = optionsNextString(args, &i)
		case "-h", "--help":
			help()
			return nil
		default:
			if i == len(args)-1 && opts.OrgURL == "" && opts.RepoURL == "" &&
				opts.UserURL == "" {
				opts.RepoURL = arg
			} else {
				fmt.Printf("Uknown option %s\n\n", arg)
				help()
				return nil
			}
		}
	}

	return opts
}
