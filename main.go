package main

import (
	"os"
	"regexp"
)

var (
	appRoot     string
	regexes     map[string]*regexp.Regexp
	assignRegex *regexp.Regexp
	report      []ReportElem
)

func init() {
	appRoot, _ = os.Getwd()
	// TODO update regex to look for things like:
	// TODO ability to add/filter regex
	// client("AKAI32fJ334...",
	regexes = map[string]*regexp.Regexp{
		"github":   regexp.MustCompile(`[g|G][i|I][t|T][h|H][u|U][b|B].*(=|:|:=|<-).*\w+.*`),
		"aws":      regexp.MustCompile(`[a|A][w|W][s|S].*(=|:=|:|<-).*\w+.*`),
		"heroku":   regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].*(=|:=|:|<-).*\w+.*`),
		"facebook": regexp.MustCompile(`[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*(=|:=|:|<-).*\w+.*`),
		"twitter":  regexp.MustCompile(`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*(=|:=|:|<-).*\w+.*`),
		"reddit":   regexp.MustCompile(`[r|R][e|E][d|D][d|D][i|I][t|T].*(=|:=|:|<-).*\w+.*`),
		"twilio":   regexp.MustCompile(`[t|T][w|W][i|I][l|L][i|I][o|O].*(=|:=|:|<-).*\w+.*`),
	}
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)
}

func main() {
	args := os.Args[2:]
	repoUrl := os.Args[1]
	opts := parseOptions(args, repoUrl)
	start(opts, repoUrl)
}
