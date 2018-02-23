package main

import (
	"fmt"
	"os"
	"strconv"
)

const usage = `usage: gitleaks [options] <url>

Options:
	-c 			Concurrency factor (default is 10)
	-u --user 		Git user url
	-r --repo 		Git repo url
	-o --org 		Git organization url
	-s --strict 		Strict mode uses stopwords in config.yml 
	-b --b64Entropy 	Base64 entropy cutoff (default is 70)
	-x --hexEntropy  	Hex entropy cutoff (default is 40)
	-e --entropy	Enable entropy		
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
	Entropy bool
}

// help prints the usage string and exits
func help() {
	os.Stderr.WriteString(usage)
	os.Exit(1)
}

// optionsNextInt is a parseOptions helper that returns the value (int) of an option if valid
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

// optionsNextString is a parseOptions helper that returns the value (string) of an option if valid
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
		Entropy: false,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-s", "--strict":
			opts.Strict = true
		case "-b", "--b64Entropy":
			opts.B64EntropyCutoff = optionsNextInt(args, &i)
		case "-x", "--hexEntropy":
			opts.HexEntropyCutoff = optionsNextInt(args, &i)
		case "-e", "--entropy":
			opts.Entropy = true
		case "-c":
			opts.Concurrency = optionsNextInt(args, &i)
		case "-o", "--org":
			opts.OrgURL = optionsNextString(args, &i)
		case "-u", "--user":
			opts.UserURL = optionsNextString(args, &i)
		case "-r", "--repo":
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
