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
	regexes     map[string]*regexp.Regexp
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

	regexes = map[string]*regexp.Regexp{
		"RSA":      regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----"),
		"SSH":      regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"),
		"Facebook": regexp.MustCompile("(?i)facebook.*['|\"][0-9a-f]{32}['|\"]"),
		"Twitter":  regexp.MustCompile("(?i)twitter.*['|\"][0-9a-zA-Z]{35,44}['|\"]"),
		"Github":   regexp.MustCompile("(?i)github.*[['|\"]0-9a-zA-Z]{35,40}['|\"]"),
		"AWS":      regexp.MustCompile("AKIA[0-9A-Z]{16}"),
		"Reddit":   regexp.MustCompile("(?i)reddit.*['|\"][0-9a-zA-Z]{14}['|\"]"),
		"Heroku":   regexp.MustCompile("(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
		// "Custom": regexp.MustCompile(".*")
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
