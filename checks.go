package main

import (
	"bytes"
	_ "fmt"
	"regexp"
)

func checkRegex(diff []byte) {
	var re *regexp.Regexp
	var found string
	lines := bytes.Split(diff, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		for _, v := range regexes {
			re = regexp.MustCompile(v)
			found = re.FindString(string(line))
			if len(found) == 0 {
				continue
			}
		}
	}
}
