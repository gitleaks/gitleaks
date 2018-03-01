package main

import (
	"fmt"
	_ "fmt"
	"go.uber.org/zap"
	_ "io/ioutil"
	"os"
	"regexp"
	_ "time"
)

const EXIT_CLEAN = 0
const EXIT_FAILURE = 1
const EXIT_LEAKS = 2

// package globals
var (
	regexes       map[string]*regexp.Regexp
	stopWords     []string
	base64Chars   string
	hexChars      string
	assignRegex   *regexp.Regexp
	fileDiffRegex *regexp.Regexp
	logger        *zap.Logger
	opts          *Options
)

func init() {
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"
	stopWords = []string{"setting", "info", "env", "environment"}
	fileDiffRegex = regexp.MustCompile("diff --git a.+b/")
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)

	// TODO Externalize regex... this is tricky making it yml compliant
	regexes = map[string]*regexp.Regexp{
		"PKCS8":    regexp.MustCompile("-----BEGIN PRIVATE KEY-----"),
		"RSA":      regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----"),
		"SSH":      regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"),
		"Facebook": regexp.MustCompile("(?i)facebook.*['|\"][0-9a-f]{32}['|\"]"),
		"Twitter":  regexp.MustCompile("(?i)twitter.*['|\"][0-9a-zA-Z]{35,44}['|\"]"),
		"Github":   regexp.MustCompile("(?i)github.*[['|\"]0-9a-zA-Z]{35,40}['|\"]"),
		"AWS":      regexp.MustCompile("AKIA[0-9A-Z]{16}"),
		"Reddit":   regexp.MustCompile("(?i)reddit.*['|\"][0-9a-zA-Z]{14}['|\"]"),
		"Heroku":   regexp.MustCompile("(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
	}
}

func main() {
	args := os.Args[1:]
	opts = newOpts(args)
	owner := newOwner()
	os.Exit(owner.auditRepos())
}

func failF(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(EXIT_FAILURE)
}
