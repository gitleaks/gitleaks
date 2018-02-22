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
	"strconv"
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
		"github":   regexp.MustCompile(`[g|G][i|I][t|T][h|H][u|U][b|B].*(=|:=|<-).*\w+.*`),
		"aws":      regexp.MustCompile(`[a|A][w|W][s|S].*(=|:=|:|<-).*\w+.*`),
		"heroku":   regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].*(=|:=|<-).*\w+.*`),
		"facebook": regexp.MustCompile(`[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*(=|:=|<-).*\w+.*`),
		"twitter":  regexp.MustCompile(`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*(=|:=|<-).*\w+.*`),
		"reddit":   regexp.MustCompile(`[r|R][e|E][d|D][d|D][i|I][t|T].*(=|:=|<-).*\w+.*`),
		"twilio":   regexp.MustCompile(`[t|T][w|W][i|I][l|L][i|I][o|O].*(=|:=|<-).*\w+.*`),
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
		token 	   string
		repoList   []RepoElem
		maxPage    int
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

	if opts.Token != "" {
		token = fmt.Sprintf("access_token=%s&", opts.Token)
	}

	curPage := 1
	perPage := 100

	for {
		resp, err := http.Get(fmt.Sprintf("https://api.github.com/%s/%s/repos?%sper_page=%v&page=%v", targetType, target, token, perPage, curPage))
		if err != nil || resp.StatusCode != 200{
			log.Fatal(err)
		}

		if curPage == 1 {
			maxPage = getMaxPages(resp.Header.Get("Link"))
		}
		
		defer resp.Body.Close()
		var partsRepoList []RepoElem
		json.NewDecoder(resp.Body).Decode(&partsRepoList)
		repoList = append(repoList, partsRepoList...)

		if curPage == maxPage {
			break
		}
		curPage += 1
	}
	fmt.Printf("Found %d repositories for \x1b[37;1m%s\x1b[0m\n", len(repoList), target)
	return repoList
}

func getMaxPages(linkHeader string) int {
	links := strings.Split(linkHeader, ",")

	re_last := regexp.MustCompile(`rel="last"`)
	re_page := regexp.MustCompile(`[?&]page=(\d+)`)
	var max_page int
	for _, link := range links {
		if re_last.MatchString(link) {
			max_pages_s := re_page.FindStringSubmatch(link)
			max_page, _ = strconv.Atoi(max_pages_s[1])
		}
	}

	return max_page
}
