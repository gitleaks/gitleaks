package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	appRoot     string
	regexes     []*regexp.Regexp
	stopWords   []string
	base64Chars string
	hexChars    string
	opts        *Options
	assignRegex *regexp.Regexp
)

// RepoElem used for parsing json from github api
type RepoElem struct {
	RepoURL string `json:"html_url"`
}

func init() {
	var (
		err error
	)

	appRoot, err = os.Getwd()
	if err != nil {
		log.Fatalf("Can't get working dir: %s", err)
	}
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"

	stopWords = []string{"setting", "Setting", "SETTING", "info",
		"Info", "INFO", "env", "Env", "ENV", "environment", "Environment", "ENVIRONMENT"}

	regexes = []*regexp.Regexp{
		regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----"),
		regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"),
		regexp.MustCompile("[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]"),
		regexp.MustCompile("[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"),
		regexp.MustCompile("[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]"),
		regexp.MustCompile("AKIA[0-9A-Z]{16}"),
		regexp.MustCompile("[r|R][e|E][d|D][d|D][i|I][t|T].*['|\"][0-9a-zA-Z]{14}['|\"]"),
		regexp.MustCompile("[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
	}
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)
}

func main() {
	args := os.Args[1:]
	opts = parseOptions(args)
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
