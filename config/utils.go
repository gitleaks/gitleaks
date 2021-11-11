package config

import "regexp"

// anyRegexMatch matched an interface to a regular expression. The interface f can
// be a string type or go-git *object.File type.
func anyRegexMatch(f string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if regexMatched(f, re) {
			return true
		}
	}
	return false
}

// regexMatched matched an interface to a regular expression. The interface f can
// be a string type or go-git *object.File type.
func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
}
