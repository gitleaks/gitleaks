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
	-h --help 		Display this message
`

type Options struct {
	Concurrency int
}

func help() {
	os.Stderr.WriteString(usage)
	os.Exit(1)
}

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

func optionsNextString(args []string, i *int) string {
	if len(args) > *i+1 {
		*i++
	} else {
		help()
	}
	return args[*i]
}

func parseOptions(args []string, repoUrl string) *Options {
	opts := &Options{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-c":
			opts.Concurrency = optionsNextInt(args, &i)
		case "-h", "--help":
			help()
			return nil
		default:
			fmt.Printf("Uknown option %s\n\n", arg)
			help()
			return nil
		}
	}

	return opts
}
