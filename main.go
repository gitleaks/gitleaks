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
	base64Chars string
	hexChars    string
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
		"github":   regexp.MustCompile(`[gG][iI][tT][hH][uU][bB].*(=|:=|<-).*\w+.*`),
		"aws":      regexp.MustCompile(`[aA][wW][sS].*(=|:=|:|<-).*\w+.*`),
		"heroku":   regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].*(=|:=|<-).*\w+.*`),
		"facebook": regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].*(=|:=|<-).*\w+.*`),
		"twitter":  regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*(=|:=|<-).*\w+.*`),
		"reddit":   regexp.MustCompile(`[rR][eE][dD][dD][iI][tT].*(=|:=|<-).*\w+.*`),
		"twilio":   regexp.MustCompile(`[tT][wW][iI][lL][iI][oO].*(=|:=|<-).*\w+.*`),
	}
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"
}

func main() {
	args := os.Args[1:]
	opts := parseOptions(args)
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
		targetType = "orgs"
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
