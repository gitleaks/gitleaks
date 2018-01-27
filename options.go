package main

import (
	"fmt"
	"os"
)

// TODO regex on type.. user/organization can be treated as the same:
// 	hittps://github.com/<user or org>
// 	hittps://github.com/<user or org>/repo
const usage = `usage: gogethunt [options]
	
Options:
	-u --user		Target user
	-r --repo 		Target repo
	-o --org 		Target organization
    -h --help 		Display this message
	-e --entropy	Enable entropy detection
	-r --regex 		Enable regex detection
`

type Options struct {
	User string
	Repo string
	Org  string
}

func help() {
	os.Stderr.WriteString(usage)
	os.Exit(1)
}

func optionsNextString(args []string, i *int) string {
	if len(args) > *i+1 {
		*i++
	} else {
		help()
	}
	return args[*i]
}

func parseOptions(args []string) *Options {
	opts := &Options{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-o", "--org":
			opts.Org = optionsNextString(args, &i)
		case "-r", "--repo":
			opts.Repo = optionsNextString(args, &i)
		case "-u", "--user":
			opts.User = optionsNextString(args, &i)
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
