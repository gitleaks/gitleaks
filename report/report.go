package report

import (
	"github.com/zricethezav/gitleaks/v8/config"
	"os"
	"strings"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE             = "CWE-798"
	CWE_DESCRIPTION = "Use of Hard-coded Credentials"
)

func Write(findings []Finding, cfg config.Config, ext string, reportPath string) error {
	ext = strings.ToLower(ext)
	if ext == "" {
		ext = "json"
	}

	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}

	switch ext {
	case ".json", "json":
		err = writeJson(findings, file)
	case ".csv", "csv":
		err = writeCsv(findings, file)
	case ".xml", "xml", ".junit", "junit":
		err = writeJunit(findings, file)
	case ".sarif", "sarif":
		err = writeSarif(cfg, findings, file)
	}

	return err
}
