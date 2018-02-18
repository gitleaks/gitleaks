package main

import (
	"encoding/json"
	"fmt"
	_ "io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	appRoot     string
	regexes     map[string]*regexp.Regexp
	assignRegex *regexp.Regexp
)

func init() {
	var err error
	appRoot, err = os.Getwd()
	if err != nil {
		log.Fatalf("Can't get working dir: %s", err)
	}

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
	args := os.Args[1:]
	opts := parseOptions(args)
	fmt.Println(opts)
	if opts.RepoURL != "" {
		start(opts)
	} else if opts.UserURL != "" || opts.OrgURL != "" {
		repoList := repoScan(opts)
		for _, repo := range repoList {
			opts.RepoURL = repo.RepoURL
			start(opts)
		}
	}
}

// RepoElem used for parsing json from github api
type RepoElem struct {
	RepoURL string `json:"html_url"`
}

// repoScan attempts to parse all repo urls from an organization or user
func repoScan(opts *Options) []RepoElem {
	var (
		targetURL  string
		target     string
		targetType string
		repoList   []RepoElem
	)

	if opts.UserURL != "" {
		targetURL = opts.UserURL
		targetType = "users"
	} else {
		targetURL = opts.OrgURL
		targetType = "org"
	}
	splitTargetURL := strings.Split(targetURL, "/")
	target = splitTargetURL[len(splitTargetURL)-1]

	resp, err := http.Get(fmt.Sprintf("https://api.github.com/%s/%s/repos", targetType, target))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&repoList)
	return repoList
}
