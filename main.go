package main

import (
	_ "fmt"
	"github.com/mitchellh/go-homedir"
	"log"
	_"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"go.uber.org/zap"
	_"time"
	"go.uber.org/zap/zapcore"
)

const EXIT_CLEAN = 0
const EXIT_FAILURE = 1
const EXIT_LEAKS = 2

var (
	regexes            map[string]*regexp.Regexp
	stopWords          []string
	base64Chars        string
	hexChars           string
	assignRegex        *regexp.Regexp
	fileDiffRegex      *regexp.Regexp
	gitLeaksPath       string
	gitLeaksClonePath  string
	gitLeaksReportPath string
	logger  *zap.Logger
)

func init() {
	base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	hexChars = "1234567890abcdefABCDEF"
	stopWords = []string{"setting", "info", "env", "environment"}
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
		// "Custom": regexp.MustCompile(".*")
	}
	fileDiffRegex = regexp.MustCompile("diff --git a.+b/")
	assignRegex = regexp.MustCompile(`(=|:|:=|<-)`)

	// gitleaks dir defaults to $HOME/.gitleaks if no env var GITLEAKS_HOME is present.
	gitLeaksPath = os.Getenv("GITLEAKS_HOME")
	if gitLeaksPath == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			log.Fatal("Cant find home dir")
		}
		gitLeaksPath = filepath.Join(homeDir, ".gitleaks")
	}

	if _, err := os.Stat(gitLeaksPath); os.IsNotExist(err) {
		os.Mkdir(gitLeaksPath, os.ModePerm)
	}
	gitLeaksClonePath = filepath.Join(gitLeaksPath, "clones")
	if _, err := os.Stat(gitLeaksClonePath); os.IsNotExist(err) {
		os.Mkdir(gitLeaksClonePath, os.ModePerm)
	}
	gitLeaksReportPath = filepath.Join(gitLeaksPath, "report")
	if _, err := os.Stat(gitLeaksReportPath); os.IsNotExist(err) {
		os.Mkdir(gitLeaksReportPath, os.ModePerm)
	}
}

func main() {
	// TODO abstract logging
	atom := zap.NewAtomicLevel()
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = ""
	logger = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		atom,
	))
	logger.Info("HEY")
	atom.SetLevel(zap.InfoLevel)
	logger.Info("HEY")


	args := os.Args[1:]
	opts := parseOptions(args)
	owner := newOwner(opts)
	owner.auditRepos(opts)
	// repos := getRepos(opts, owner)
	// start(repos, owner, opts)
}
