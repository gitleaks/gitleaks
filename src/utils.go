package gitleaks

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
)

//writeReportCSV writes a report to a file in CSV format
func writeReportCSV(leaks []Leak, dest string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"repo", "line", "commit", "offender", "rule", "info", "tags", "severity", "commitMsg", "author", "email", "file", "date"})
	for _, leak := range leaks {
		w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Rule, leak.Info, leak.Tags, leak.Severity, leak.Message, leak.Author, leak.Email, leak.File, leak.Date.Format(time.RFC3339)})
	}
	w.Flush()
	return nil
}

//writeReportJSON writes a report to a file in JSON format
func writeReportJSON(leaks []Leak, dest string) error {
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "\t")
	if _, err := f.WriteString("[\n"); err != nil {
		return err
	}
	for i := 0; i < len(leaks); i++ {
		if err := encoder.Encode(leaks[i]); err != nil {
			return err
		}
		// for all but the last leak, seek back and overwrite the newline appended by Encode() with comma & newline
		if i+1 < len(leaks) {
			if _, err := f.Seek(-1, 1); err != nil {
				return err
			}
			if _, err := f.WriteString(",\n"); err != nil {
				return err
			}
		}
	}
	if _, err := f.WriteString("]"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

//writeReportS3 writes a report to a file in AWS S3 object storage in JSON format
func writeReportS3(leaks []Leak, dest string) error {

	tmpReport, err := ioutil.TempFile("/tmp", ".gitleak-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpReport.Name())

	err = writeReportJSON(leaks, tmpReport.Name())
	if err != nil {
		return err
	}

	// discovery bucket and path
	r := regexp.MustCompile(`s3://(.*)/(.*)`)
	match := r.FindStringSubmatch(dest)
	if match == nil {
		return errors.New("No valid match for s3 Report. Eg s3://bucket/object/path")
	}
	if len(match) <= 2 {
		return fmt.Errorf("Object not found. Match found: %v", match)
	}
	awsBucket := match[1]
	awsObject := fmt.Sprintf("%s/%s.json", match[2], filepath.Base(opts.Repo))

	// read tmpReport and save to S3 path (reportDest)
	s, err := session.NewSession(&aws.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Open the file for use
	file, err := os.Open(tmpReport.Name())
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size and read the file content into a buffer
	fileInfo, _ := file.Stat()
	var size int64 = fileInfo.Size()
	buffer := make([]byte, size)
	file.Read(buffer)

	log.Printf("Sending report to object s3://%s/%s\n", awsBucket, awsObject)
	_, err = s3.New(s).PutObject(&s3.PutObjectInput{
		Bucket:             aws.String(awsBucket),
		Key:                aws.String(awsObject),
		ACL:                aws.String("private"),
		Body:               bytes.NewReader(buffer),
		ContentLength:      aws.Int64(size),
		ContentType:        aws.String(http.DetectContentType(buffer)),
		ContentDisposition: aws.String("attachment"),
	})
	return err
}

//writeReportSyslog writes a report to a syslog server JSON format, one message by report.
func writeReportSyslog(leaks []Leak, dest string) error {

	r := regexp.MustCompile(`syslog://(.*):(.*:.*)/(.*)$`)
	match := r.FindStringSubmatch(dest)
	if match == nil {
		return errors.New("No valid match for TCP Report. Eg syslog://TCP:SERVER:PORT/tag")
	}
	if len(match) <= 1 {
		return fmt.Errorf("IP/DNS and port not found. Match found: %v", match)
	}
	destSyslogProto := strings.ToLower(match[1])
	destSyslogIPPort := match[2]
	destSyslogTag := match[3]

	sysLog, err := syslog.Dial(destSyslogProto, destSyslogIPPort,
		syslog.LOG_INFO|syslog.LOG_DAEMON, destSyslogTag)
	if err != nil {
		log.Fatal(err)
	}
	// defer syslog.Close()

	for _, leak := range leaks {
		leakStr, err := json.Marshal(leak)
		if err != nil {
			log.Errorf("Error parsing leak to send to gelf")
			continue
		}
		fmt.Println(string(leakStr))
		fmt.Fprintf(sysLog, string(leakStr))
	}

	return nil
}

// writeReport writes a report to a file specified in the --report= option.
// Default format for report is JSON. You can use the --csv option to write the report as a csv
func writeReport(leaks []Leak) error {
	if len(leaks) == 0 {
		return nil
	}
	var err error = nil
	reports := strings.Split(opts.Report, ",")
	for _, dest := range reports {
		log.Infof("writing report to base path %s", dest)

		if strings.HasSuffix(dest, ".csv") {
			err = writeReportCSV(leaks, dest)
			if err != nil {
				return err
			}
		} else if strings.HasPrefix(dest, "s3://") {
			err = writeReportS3(leaks, dest)
			if err != nil {
				return err
			}
		} else if strings.HasPrefix(dest, "syslog://") {
			err = writeReportSyslog(leaks, dest)
			if err != nil {
				return err
			}
		} else {
			err = writeReportJSON(leaks, dest)
			if err != nil {
				return err
			}
		}
	}
	return err
}

// check rule will inspect a single line and return a leak if it encounters one
func (rule *Rule) check(line string, commit *Commit) (*Leak, error) {
	var (
		match       string
		fileMatch   string
		entropy     float64
		entropyWord string
	)

	for _, f := range rule.fileTypes {
		fileMatch = f.FindString(commit.filePath)
		if fileMatch != "" {
			break
		}
	}

	if fileMatch == "" && len(rule.fileTypes) != 0 {
		return nil, nil
	}

	if rule.entropies != nil {
		if rule.entropyROI == "word" {
			words := strings.Fields(line)
			for _, word := range words {
				_entropy := getShannonEntropy(word)
				for _, e := range rule.entropies {
					if _entropy > e.v1 && _entropy < e.v2 {
						entropy = _entropy
						entropyWord = word
						goto postEntropy
					}
				}
			}
		} else {
			_entropy := getShannonEntropy(line)
			for _, e := range rule.entropies {
				if _entropy > e.v1 && _entropy < e.v2 {
					entropy = _entropy
					entropyWord = line
					goto postEntropy
				}
			}
		}
	}

postEntropy:
	if rule.regex != nil {
		match = rule.regex.FindString(line)
	}

	if match != "" && entropy != 0.0 {
		return newLeak(line, fmt.Sprintf("%s regex match and entropy met at %.2f", rule.regex.String(), entropy), entropyWord, rule, commit), nil
	} else if match != "" && rule.entropies == nil {
		return newLeak(line, fmt.Sprintf("%s regex match", rule.regex.String()), match, rule, commit), nil
	} else if entropy != 0.0 && rule.regex.String() == "" {
		return newLeak(line, fmt.Sprintf("entropy met at %.2f", entropy), entropyWord, rule, commit), nil
	}
	return nil, nil
}

// inspect will parse each line of the git diff's content against a set of regexes or
// a set of regexes set by the config (see gitleaks.toml for example). This function
// will skip lines that include a whitelisted regex. A list of leaks is returned.
// If verbose mode (-v/--verbose) is set, then checkDiff will log leaks as they are discovered.
func inspect(commit *Commit) []Leak {
	var leaks []Leak
	lines := strings.Split(commit.content, "\n")

	for _, line := range lines {
		for _, rule := range config.Rules {
			if isLineWhitelisted(line) {
				break
			}
			leak, err := rule.check(line, commit)
			if err != nil || leak == nil {
				continue
			}
			leaks = append(leaks, *leak)
		}
	}
	return leaks
}

// isLineWhitelisted returns true iff the line is matched by at least one of the whiteListRegexes.
func isLineWhitelisted(line string) bool {
	for _, wRe := range config.WhiteList.regexes {
		whitelistMatch := wRe.FindString(line)
		if whitelistMatch != "" {
			return true
		}
	}
	return false
}

func newLeak(line string, info string, offender string, rule *Rule, commit *Commit) *Leak {
	leak := &Leak{
		Line:     line,
		Commit:   commit.sha,
		Offender: offender,
		Rule:     rule.description,
		Info:     info,
		Author:   commit.author,
		Email:    commit.email,
		File:     commit.filePath,
		Repo:     commit.repoName,
		Message:  commit.message,
		Date:     commit.date,
		Tags:     strings.Join(rule.tags, ", "),
		Severity: rule.severity,
	}
	if opts.Redact {
		leak.Offender = "REDACTED"
		leak.Line = strings.Replace(line, offender, "REDACTED", -1)
	}

	if opts.Verbose {
		leak.log()
	}
	return leak
}

// discoverRepos walks all the children of `path`. If a child directory
// contain a .git subdirectory then that repo will be added to the list of repos returned
func discoverRepos(ownerPath string) ([]*Repo, error) {
	var (
		err    error
		repoDs []*Repo
	)
	files, err := ioutil.ReadDir(ownerPath)
	if err != nil {
		return repoDs, err
	}
	for _, f := range files {
		repoPath := path.Join(ownerPath, f.Name())
		if f.IsDir() && containsGit(repoPath) {
			repoDs = append(repoDs, &Repo{
				name: f.Name(),
				path: repoPath,
			})
		}
	}
	return repoDs, err
}

func (leak Leak) log() {
	b, _ := json.MarshalIndent(leak, "", "   ")
	fmt.Println(string(b))
}

func containsGit(repoPath string) bool {
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return false
	}
	return true
}
