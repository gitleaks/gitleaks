package main

import (
	"os"
	"regexp"
)

// ExitClean : no leaks have been found
const ExitClean = 0

// ExitFailure : gitleaks has encountered an error or SIGINT
const ExitFailure = 1

// ExitLeaks : leaks are present in scanned repos
const ExitLeaks = 2

// package globals
var (
	regexes       map[string]*regexp.Regexp
	externalRegex []*regexp.Regexp
	stopWords     []string
	base64Chars   string
	hexChars      string
	assignRegex   *regexp.Regexp
	fileDiffRegex *regexp.Regexp
	opts          *Options
	pwd           string
)

func init() {
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"
	stopWords = []string{"setting", "info", "env", "environment"}
	fileDiffRegex = regexp.MustCompile("diff --git a.+b/")
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)
	regexes = map[string]*regexp.Regexp{
		"PKCS8":    regexp.MustCompile("-----BEGIN PRIVATE KEY-----"),
		"RSA":      regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----"),
		"DSA":      regexp.MustCompile("-----BEGIN DSA PRIVATE KEY-----"),
		"SSH":      regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"),
		"Facebook": regexp.MustCompile("(?i)facebook.*['\"][0-9a-f]{32}['\"]"),
		"Twitter":  regexp.MustCompile("(?i)twitter.*['\"][0-9a-zA-Z]{35,44}['\"]"),
		"Github":   regexp.MustCompile("(?i)github.*['\"][0-9a-zA-Z]{35,40}['\"]"),
		"AWS":      regexp.MustCompile("AKIA[0-9A-Z]{16}"),
		"Reddit":   regexp.MustCompile("(?i)reddit.*['\"][0-9a-zA-Z]{14}['\"]"),
		"Heroku":   regexp.MustCompile("(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
	}
}

func main() {
	args := os.Args[1:]
	opts = newOpts(args)
	owner := newOwner()
	os.Exit(owner.auditRepos())
}
