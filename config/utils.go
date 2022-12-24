package config

import (
	"os"
	"regexp"

	"github.com/rs/zerolog/log"
)

func anyRegexMatch(f string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if regexMatched(f, re) {
			return true
		}
	}
	return false
}

func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
}

func ValidateReportPath(path string) {
	fsInfo, err := os.Stat(path)
	if err != nil {
		log.Fatal().Err(err).Msg("bad report path")
	}
	if fsInfo.IsDir() {
		log.Fatal().Err(err).Msg("report path make must be a file")
	}
}
