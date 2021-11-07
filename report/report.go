package report

import (
	"os"
	"strings"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE             = "CWE-798"
	CWE_DESCRIPTION = "Use of Hard-coded Credentials"
)

func Write(findings []*Finding, ext string, reportPath string) error {
	if len(findings) == 0 {
		return nil
	}
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	ext = strings.ToLower(ext)
	switch ext {
	case ".json", "json":
		writeJson(findings, file)
	case ".csv", "csv":
		writeCsv(findings, file)
	case ".sarif", "sarif":

	}

	return nil
}
