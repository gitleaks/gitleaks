package report

import (
	"os"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE             = "CWE-798"
	CWE_DESCRIPTION = "Use of Hard-coded Credentials"
)

func Write(findings []Finding, cfg config.Config, ext string, reportPath string) error {
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	ext = strings.ToLower(ext)
	switch ext {
	case ".json", "json":
		err = writeJson(findings, file)
	case ".csv", "csv":
		err = writeCsv(findings, file)
	case ".xml", "junit":
		err = writeJunit(findings, file)
	case ".sarif", "sarif":
		err = writeSarif(cfg, findings, file)
	}

	return err
}
