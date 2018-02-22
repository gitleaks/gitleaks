package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"gopkg.in/yaml.v2"
)

var (
	appRoot     string
	regexes     []*regexp.Regexp
	stopWords 	[]string
	assignRegex *regexp.Regexp
	base64Chars string
	hexChars    string
)

// config
type conf struct {
	Regexes []string `yaml:"regexes"`
	StopWords []string	`yaml:"stopwords"`
}

// RepoElem used for parsing json from github api
type RepoElem struct {
	RepoURL string `json:"html_url"`
}

func init() {
	var (
		err error
		c conf
	)

	appRoot, err = os.Getwd()
	if err != nil {
		log.Fatalf("Can't get working dir: %s", err)
	}
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"

	// read config
	ymlFile, err := ioutil.ReadFile("config.yml")
	if err != nil {
		log.Printf("could not load config.yml #%v ", err)
	}
	err = yaml.Unmarshal(ymlFile, &c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	// regex from config
	stopWords = c.StopWords
	for _, re := range c.Regexes {
		regexes = append(regexes, regexp.MustCompile(re))
	}
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)
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
